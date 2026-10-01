use std::{
    io::SeekFrom,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, bail};
use russh::{
    client::{self, AuthResult},
    keys::{
        self, PrivateKeyWithHashAlg, PublicKeyOrCertificate,
        ssh_key::{Algorithm, HashAlg},
    },
};
use serde_json::{Value, json};
use tokio::{
    fs::{self, File, OpenOptions},
    io::{
        AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt,
        BufReader,
    },
    net::ToSocketAddrs,
};
use uuid::Uuid;

use crate::protocol::{MAX_JSON_LINE, SUBSYSTEM_NAME, TRANSFER_CHUNK_SIZE, write_jsonl};

#[derive(Debug, Clone)]
pub struct ConnectionOptions {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub identity_file: PathBuf,
    pub known_hosts_file: PathBuf,
}

#[derive(Debug, Clone)]
pub enum ClientCommand {
    List { path: Option<String> },
    Rm { path: String, recursive: bool },
    Upload { local: PathBuf, remote: String },
    Download { remote: String, local: PathBuf },
    Search { query: String, path: Option<String> },
    Pwd,
    Cd { path: String },
    Mkdir { path: String },
}

pub fn default_ssh_directory() -> anyhow::Result<PathBuf> {
    #[cfg(windows)]
    let home = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .context("USERPROFILE must be set")?;
    #[cfg(not(windows))]
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME must be set")?;
    Ok(home.join(".ssh"))
}

pub async fn default_known_hosts_path() -> anyhow::Result<PathBuf> {
    Ok(default_ssh_directory()?.join("known_hosts"))
}

struct JftpClientHandler {
    host: String,
    port: u16,
    known_hosts: PathBuf,
}

impl client::Handler for JftpClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = server_public_key.public_key();
        match keys::check_known_hosts_path(&self.host, self.port, &key, &self.known_hosts) {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(keys::Error::KeyChanged { line }) => {
                eprintln!(
                    "WARNING: SSH host key for {}:{} differs from the key in {} on line {}.",
                    self.host,
                    self.port,
                    self.known_hosts.display(),
                    line
                );
                eprintln!(
                    "Current fingerprint: {}. Verify the change and update known_hosts manually.",
                    key.fingerprint(HashAlg::Sha256)
                );
                return Ok(false);
            }
            Err(error) => {
                return Err(anyhow::anyhow!(error).context(format!(
                    "could not check known hosts file {}",
                    self.known_hosts.display()
                )));
            }
        }

        if !confirm_host_key(&self.host, self.port, &key, &self.known_hosts).await? {
            return Ok(false);
        }

        // Another client may have added the host while this confirmation was
        // waiting for input. Re-check before appending, and never override a
        // changed key.
        match keys::check_known_hosts_path(&self.host, self.port, &key, &self.known_hosts) {
            Ok(true) => Ok(true),
            Ok(false) => {
                add_known_host(&self.host, self.port, &key, &self.known_hosts).await?;
                eprintln!(
                    "Added {}:{} to {}",
                    self.host,
                    self.port,
                    self.known_hosts.display()
                );
                Ok(true)
            }
            Err(keys::Error::KeyChanged { line }) => {
                eprintln!(
                    "A different SSH host key for {}:{} was added to {} on line {} while confirming. Refusing the connection.",
                    self.host,
                    self.port,
                    self.known_hosts.display(),
                    line
                );
                Ok(false)
            }
            Err(error) => Err(anyhow::anyhow!(error).context(format!(
                "could not check known hosts file {}",
                self.known_hosts.display()
            ))),
        }
    }
}

async fn confirm_host_key(
    host: &str,
    port: u16,
    key: &russh::keys::ssh_key::PublicKey,
    known_hosts: &Path,
) -> anyhow::Result<bool> {
    let endpoint = if port == 22 {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    };
    let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
    let algorithm = format!("{:?}", key.algorithm());
    let known_hosts = known_hosts.display().to_string();
    tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
        use std::io::{self, Write};

        eprintln!("The authenticity of host '{endpoint}' cannot be established.");
        eprintln!("{algorithm} key fingerprint is {fingerprint}.");
        eprintln!("Verify this fingerprint before trusting the server.");
        eprint!("Trust this server and add its key to {known_hosts}? (yes/no): ");
        io::stderr().flush()?;

        let mut response = String::new();
        if io::stdin().read_line(&mut response)? == 0 {
            return Ok(false);
        }
        Ok(matches!(
            response.trim().to_ascii_lowercase().as_str(),
            "yes" | "y"
        ))
    })
    .await
    .context("could not read host-key confirmation")?
}

async fn add_known_host(
    host: &str,
    port: u16,
    key: &russh::keys::ssh_key::PublicKey,
    known_hosts: &Path,
) -> anyhow::Result<()> {
    if let Some(parent) = known_hosts
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("cannot create SSH directory {}", parent.display()))?;
    }

    let mut options = OpenOptions::new();
    options.read(true).append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(known_hosts)
        .await
        .with_context(|| format!("cannot open known hosts file {}", known_hosts.display()))?;

    if file.metadata().await?.len() > 0 {
        file.seek(SeekFrom::End(-1)).await?;
        let mut last_byte = [0u8; 1];
        file.read_exact(&mut last_byte).await?;
        file.seek(SeekFrom::End(0)).await?;
        if last_byte[0] != b'\n' {
            file.write_all(b"\n").await?;
        }
    }
    if port == 22 {
        file.write_all(format!("{host} ").as_bytes()).await?;
    } else {
        file.write_all(format!("[{host}]:{port} ").as_bytes())
            .await?;
    }
    file.write_all(key.to_openssh()?.as_bytes()).await?;
    file.write_all(b"\n").await?;
    file.flush().await?;
    file.sync_all().await?;
    Ok(())
}

pub struct ClientSession<R, W> {
    reader: BufReader<R>,
    writer: W,
    cwd: String,
    _ssh: client::Handle<JftpClientHandler>,
}

impl<R, W> ClientSession<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub async fn run_command(&mut self, command: ClientCommand) -> anyhow::Result<bool> {
        match command {
            ClientCommand::List { path } => {
                let id = Uuid::new_v4().to_string();
                let mut request = json!({"id":id, "command":"list"});
                if let Some(path) = path {
                    request["path"] = json!(path);
                }
                self.send_request(&request).await?;
                self.read_stream(&id, false).await?;
            }
            ClientCommand::Search { query, path } => {
                let id = Uuid::new_v4().to_string();
                let mut request = json!({"id":id, "command":"search", "query":query});
                if let Some(path) = path {
                    request["path"] = json!(path);
                }
                self.send_request(&request).await?;
                self.read_stream(&id, false).await?;
            }
            ClientCommand::Rm { path, recursive } => {
                let id = Uuid::new_v4().to_string();
                self.send_request(
                    &json!({"id":id, "command":"rm", "path":path, "recursive":recursive}),
                )
                .await?;
                self.read_stream(&id, true).await?;
            }
            ClientCommand::Upload { local, remote } => self.upload(&local, &remote).await?,
            ClientCommand::Download { remote, local } => self.download(&remote, &local).await?,
            ClientCommand::Pwd => {
                let id = Uuid::new_v4().to_string();
                self.send_request(&json!({"id":id, "command":"pwd"}))
                    .await?;
                self.read_stream(&id, false).await?;
            }
            ClientCommand::Cd { path } => {
                let id = Uuid::new_v4().to_string();
                self.send_request(&json!({"id":id, "command":"cd", "path":path}))
                    .await?;
                self.read_stream(&id, false).await?;
            }
            ClientCommand::Mkdir { path } => {
                let id = Uuid::new_v4().to_string();
                self.send_request(&json!({"id":id, "command":"mkdir", "path":path}))
                    .await?;
                self.read_stream(&id, false).await?;
            }
        }
        Ok(true)
    }

    async fn send_request(&mut self, request: &Value) -> anyhow::Result<()> {
        write_jsonl(&mut self.writer, request).await
    }

    async fn next_response(&mut self) -> anyhow::Result<Value> {
        let mut line = Vec::new();
        let read = self.reader.read_until(b'\n', &mut line).await?;
        if read == 0 {
            bail!("SSH connection closed by the server");
        }
        if line.len() > MAX_JSON_LINE {
            bail!("server response exceeds the 1 MiB JSONL limit");
        }
        serde_json::from_slice(line.strip_suffix(b"\n").unwrap_or(&line))
            .context("server sent an invalid JSONL response")
    }

    async fn read_stream(&mut self, request_id: &str, cancellable: bool) -> anyhow::Result<()> {
        let mut first_error: Option<String> = None;
        let mut cancel_signal = Box::pin(tokio::signal::ctrl_c());
        let mut cancel_sent = false;
        loop {
            let response = if cancellable && !cancel_sent {
                tokio::select! {
                    response = self.next_response() => response?,
                    signal = &mut cancel_signal => {
                        signal.context("could not listen for Ctrl+C")?;
                        self.send_request(&json!({"id":Uuid::new_v4().to_string(), "command":"cancel", "path":request_id})).await?;
                        cancel_sent = true;
                        eprintln!("Cancellation requested; waiting for the server to stop safely.");
                        continue;
                    }
                }
            } else {
                self.next_response().await?
            };
            if response
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| id != request_id)
            {
                // The cancel acknowledgement has its own request ID. Show it,
                // then keep consuming the original deletion stream.
                render_response(&response);
                continue;
            }
            if response.get("type").and_then(Value::as_str) == Some("error") {
                first_error.get_or_insert_with(|| {
                    response
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("remote error")
                        .to_owned()
                });
            }
            if response.get("type").and_then(Value::as_str) == Some("cwd") {
                if let Some(path) = response.get("path").and_then(Value::as_str) {
                    self.cwd = path.to_owned();
                }
            }
            render_response(&response);
            let event_type = response
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if event_type == "done" || event_type == "cancelled" {
                if response.get("ok").and_then(Value::as_bool) == Some(false) {
                    if let Some(message) = first_error {
                        bail!("{message}");
                    }
                    bail!("remote command failed");
                }
                if response.get("had_errors").and_then(Value::as_bool) == Some(true) {
                    bail!("delete operation completed with errors");
                }
                return Ok(());
            }
        }
    }

    async fn read_expected_event(&mut self, id: &str) -> anyhow::Result<Value> {
        loop {
            let response = self.next_response().await?;
            let response_id = response
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let event_type = response
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if response_id != id {
                render_response(&response);
                continue;
            }
            if event_type == "error" {
                bail!(
                    "{}",
                    response
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("remote error")
                );
            }
            if event_type == "ready" {
                return Ok(response);
            }
            render_response(&response);
            if event_type == "done" {
                bail!("server finished before beginning the transfer");
            }
        }
    }

    async fn upload(&mut self, local: &Path, remote: &str) -> anyhow::Result<()> {
        let metadata = fs::metadata(local)
            .await
            .with_context(|| format!("cannot read local file {}", local.display()))?;
        if !metadata.is_file() {
            bail!("upload source is not a regular file: {}", local.display());
        }
        let size = metadata.len();
        let id = Uuid::new_v4().to_string();
        self.send_request(&json!({"id":id, "command":"upload", "path":remote, "size":size}))
            .await?;
        let ready = self.read_expected_event(&id).await?;
        if ready.get("transfer").and_then(Value::as_str) != Some("upload")
            || ready.get("size").and_then(Value::as_u64) != Some(size)
        {
            bail!("server returned an invalid upload handshake");
        }

        let mut source = File::open(local).await?;
        let mut remaining = size;
        let mut buffer = vec![0_u8; TRANSFER_CHUNK_SIZE];
        while remaining > 0 {
            let length =
                usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
            let read = source.read(&mut buffer[..length]).await?;
            if read == 0 {
                bail!("local upload source changed before all declared bytes were read");
            }
            self.writer.write_all(&buffer[..read]).await?;
            remaining -= read as u64;
        }
        self.writer.flush().await?;
        self.read_stream(&id, false).await?;
        Ok(())
    }

    async fn download(&mut self, remote: &str, local: &Path) -> anyhow::Result<()> {
        let id = Uuid::new_v4().to_string();
        self.send_request(&json!({"id":id, "command":"download", "path":remote}))
            .await?;
        let ready = self.read_expected_event(&id).await?;
        if ready.get("transfer").and_then(Value::as_str) != Some("download") {
            bail!("server returned an invalid download handshake");
        }
        let size = ready
            .get("size")
            .and_then(Value::as_u64)
            .context("download handshake has no valid size")?;
        let parent = local
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let leaf = local
            .file_name()
            .context("local destination file name is required")?
            .to_string_lossy();
        let temporary = parent.join(format!(".{leaf}.jftp-{}.part", Uuid::new_v4()));
        let mut destination = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .await
            .with_context(|| {
                format!("cannot create local temporary file {}", temporary.display())
            })?;
        let transfer_result = async {
            let mut remaining = size;
            let mut buffer = vec![0_u8; TRANSFER_CHUNK_SIZE];
            while remaining > 0 {
                let length =
                    usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
                self.reader
                    .read_exact(&mut buffer[..length])
                    .await
                    .context("SSH connection closed during download")?;
                destination.write_all(&buffer[..length]).await?;
                remaining -= length as u64;
            }
            destination.flush().await?;
            drop(destination);
            fs::hard_link(&temporary, local).await.with_context(|| {
                format!(
                    "local destination already exists or cannot be published: {}",
                    local.display()
                )
            })?;
            fs::remove_file(&temporary).await?;
            let response = self.next_response().await?;
            if response.get("id").and_then(Value::as_str) != Some(id.as_str())
                || response.get("type").and_then(Value::as_str) != Some("done")
            {
                bail!("server did not finish the download cleanly");
            }
            render_response(&response);
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if transfer_result.is_err() {
            let _ = fs::remove_file(&temporary).await;
        }
        transfer_result?;
        println!("saved {} bytes to {}", size, local.display());
        Ok(())
    }
}

fn render_response(response: &Value) {
    let event_type = response
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("event");
    let path = response
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let file = response
        .get("file")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match event_type {
        "entry" => {
            let kind = response
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("item");
            let size = response
                .get("size")
                .and_then(Value::as_u64)
                .map(|size| format!("  {size} B"))
                .unwrap_or_default();
            println!(
                "{kind:9} {}{size}",
                if path.is_empty() {
                    response.get("name").and_then(Value::as_str).unwrap_or("")
                } else {
                    path
                }
            );
        }
        "deleting" => println!("deleting {file}"),
        "ready" => println!(
            "{} ready ({} bytes)",
            response
                .get("transfer")
                .and_then(Value::as_str)
                .unwrap_or("transfer"),
            response
                .get("size")
                .and_then(Value::as_u64)
                .unwrap_or_default()
        ),
        "cwd" => println!("{path}"),
        "accepted" => println!(
            "{}",
            response
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("accepted")
        ),
        "done" => {
            if let Some(count) = response.get("count").and_then(Value::as_u64) {
                println!("{count} item(s)");
            }
            if let Some(deleted) = response.get("deleted").and_then(Value::as_u64) {
                println!("deleted {deleted} item(s)");
            }
        }
        "cancelled" => println!(
            "delete operation cancelled after {} item(s)",
            response
                .get("deleted")
                .and_then(Value::as_u64)
                .unwrap_or_default()
        ),
        "warning" => eprintln!(
            "warning: {}",
            response
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown issue")
        ),
        "error" => eprintln!(
            "error: {}{}",
            response
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("remote error"),
            if file.is_empty() {
                String::new()
            } else {
                format!(" ({file})")
            }
        ),
        other => println!("{other}: {response}"),
    }
}

pub async fn connect<R: ToSocketAddrs>(
    options: &ConnectionOptions,
    address: R,
) -> anyhow::Result<
    ClientSession<
        tokio::io::ReadHalf<russh::ChannelStream<client::Msg>>,
        tokio::io::WriteHalf<russh::ChannelStream<client::Msg>>,
    >,
> {
    let key_text = tokio::fs::read_to_string(&options.identity_file)
        .await
        .with_context(|| {
            format!(
                "cannot read identity file {}",
                options.identity_file.display()
            )
        })?;
    let key = match keys::decode_secret_key(&key_text, None) {
        Ok(key) => key,
        Err(_) => {
            let identity_path = options.identity_file.clone();
            let passphrase = tokio::task::spawn_blocking(move || {
                rpassword::prompt_password(format!("Passphrase for {}: ", identity_path.display()))
            })
            .await
            .context("could not prompt for private key passphrase")??;
            keys::decode_secret_key(&key_text, Some(&passphrase)).with_context(|| {
                format!(
                    "cannot decode private key {}",
                    options.identity_file.display()
                )
            })?
        }
    };
    if key.algorithm() != Algorithm::Ed25519 {
        bail!("client identity must be an Ed25519 private key");
    }

    let mut ssh = client::connect(
        Arc::new(client::Config {
            nodelay: true,
            ..Default::default()
        }),
        address,
        JftpClientHandler {
            host: options.host.clone(),
            port: options.port,
            known_hosts: options.known_hosts_file.clone(),
        },
    )
    .await
    .context("SSH connection failed")?;
    let result = ssh
        .authenticate_publickey(
            options.username.clone(),
            PrivateKeyWithHashAlg::new(Arc::new(key), None),
        )
        .await
        .context("public-key authentication failed")?;
    if result != AuthResult::Success {
        bail!(
            "server rejected the Ed25519 key for user {:?}",
            options.username
        );
    }

    let channel = ssh
        .channel_open_session()
        .await
        .context("could not open SSH session channel")?;
    channel
        .request_subsystem(true, SUBSYSTEM_NAME)
        .await
        .context("server does not accept the jftp subsystem")?;
    let (reader, writer) = tokio::io::split(channel.into_stream());
    Ok(ClientSession {
        reader: BufReader::new(reader),
        writer,
        cwd: "/".to_owned(),
        _ssh: ssh,
    })
}

pub async fn run_interactive<R, W>(session: &mut ClientSession<R, W>) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let stdin = tokio::io::stdin();
    let mut input = BufReader::new(stdin);
    println!(
        "Connected. Type help for commands; Ctrl+C cancels an active rm; exit closes the session."
    );
    loop {
        print!("jftp:{}> ", session.cwd);
        use std::io::Write;
        std::io::stdout().flush()?;
        let mut line = String::new();
        if input.read_line(&mut line).await? == 0 {
            break;
        }
        let words = match shell_words::split(&line) {
            Ok(words) => words,
            Err(error) => {
                eprintln!("{error}");
                continue;
            }
        };
        let Some(command) = words.first().map(String::as_str) else {
            continue;
        };
        if command == "exit" || command == "quit" {
            break;
        }
        if command == "help" {
            println!(
                "list [path] | search <text> [path] | cd <path> | pwd | mkdir <path> | rm <glob> | upload <local> <remote> | download <remote> <local> | exit"
            );
            continue;
        }
        let parsed = match command {
            "list" if words.len() <= 2 => Some(ClientCommand::List {
                path: words.get(1).cloned(),
            }),
            "search" if (2..=3).contains(&words.len()) => Some(ClientCommand::Search {
                query: words[1].clone(),
                path: words.get(2).cloned(),
            }),
            "pwd" if words.len() == 1 => Some(ClientCommand::Pwd),
            "cd" if words.len() == 2 => Some(ClientCommand::Cd {
                path: words[1].clone(),
            }),
            "mkdir" if words.len() == 2 => Some(ClientCommand::Mkdir {
                path: words[1].clone(),
            }),
            "rm" if words.len() == 2 => Some(ClientCommand::Rm {
                path: words[1].clone(),
                recursive: true,
            }),
            "upload" if words.len() == 3 => Some(ClientCommand::Upload {
                local: PathBuf::from(&words[1]),
                remote: words[2].clone(),
            }),
            "download" if words.len() == 3 => Some(ClientCommand::Download {
                remote: words[1].clone(),
                local: PathBuf::from(&words[2]),
            }),
            _ => None,
        };
        match parsed {
            Some(command) => {
                if let Err(error) = session.run_command(command).await {
                    eprintln!("{error:#}");
                }
            }
            None => eprintln!("invalid command; type help for usage"),
        }
    }
    Ok(())
}
