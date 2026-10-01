use std::{
    io::{IsTerminal, SeekFrom, Write as IoWrite},
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::Instant,
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
    LocalList { path: Option<PathBuf> },
    Rm { path: String, recursive: bool },
    Upload { local: PathBuf, remote: String },
    Download { remote: String, local: PathBuf },
    Search { query: String, path: Option<String> },
    Pwd,
    LocalPwd,
    Cd { path: String },
    LocalCd { path: PathBuf },
    Mkdir { path: String },
}

#[derive(Clone, Copy)]
enum OutputKind {
    List,
    Search,
    Remove,
    Transfer,
    Other,
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
    local_cwd: PathBuf,
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
                print_listing_header(path.as_deref().unwrap_or(&self.cwd), false);
                let id = Uuid::new_v4().to_string();
                let mut request = json!({"id":id, "command":"list"});
                if let Some(path) = path {
                    request["path"] = json!(path);
                }
                self.send_request(&request).await?;
                self.read_stream(&id, false, OutputKind::List).await?;
            }
            ClientCommand::LocalList { path } => {
                let directory = resolve_local_path(&self.local_cwd, path.as_deref());
                list_local_directory(&directory).await?;
            }
            ClientCommand::Search { query, path } => {
                print_listing_header(&query, true);
                let id = Uuid::new_v4().to_string();
                let mut request = json!({"id":id, "command":"search", "query":query});
                if let Some(path) = path {
                    request["path"] = json!(path);
                }
                self.send_request(&request).await?;
                self.read_stream(&id, false, OutputKind::Search).await?;
            }
            ClientCommand::Rm { path, recursive } => {
                let id = Uuid::new_v4().to_string();
                self.send_request(
                    &json!({"id":id, "command":"rm", "path":path, "recursive":recursive}),
                )
                .await?;
                self.read_stream(&id, true, OutputKind::Remove).await?;
            }
            ClientCommand::Upload { local, remote } => {
                let local = resolve_local_path(&self.local_cwd, Some(&local));
                self.upload(&local, &remote).await?;
            }
            ClientCommand::Download { remote, local } => {
                let local = resolve_local_path(&self.local_cwd, Some(&local));
                self.download(&remote, &local).await?;
            }
            ClientCommand::Pwd => {
                let id = Uuid::new_v4().to_string();
                self.send_request(&json!({"id":id, "command":"pwd"}))
                    .await?;
                self.read_stream(&id, false, OutputKind::Other).await?;
            }
            ClientCommand::LocalPwd => println!("{}", display_local_path(&self.local_cwd)),
            ClientCommand::Cd { path } => {
                let id = Uuid::new_v4().to_string();
                self.send_request(&json!({"id":id, "command":"cd", "path":path}))
                    .await?;
                self.read_stream(&id, false, OutputKind::Other).await?;
            }
            ClientCommand::LocalCd { path } => {
                self.local_cwd = change_local_directory(&self.local_cwd, &path).await?;
                println!("{}", display_local_path(&self.local_cwd));
            }
            ClientCommand::Mkdir { path } => {
                let id = Uuid::new_v4().to_string();
                self.send_request(&json!({"id":id, "command":"mkdir", "path":path}))
                    .await?;
                self.read_stream(&id, false, OutputKind::Other).await?;
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

    async fn read_stream(
        &mut self,
        request_id: &str,
        cancellable: bool,
        output: OutputKind,
    ) -> anyhow::Result<()> {
        let mut errors = Vec::new();
        let mut error_count = 0_usize;
        let mut cancel_signal = Box::pin(tokio::signal::ctrl_c());
        let mut cancel_sent = false;
        loop {
            let mut response = if cancellable && !cancel_sent {
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
                render_response(&response, output);
                continue;
            }
            if response.get("type").and_then(Value::as_str) == Some("error") {
                error_count += 1;
                if errors.len() < 10 {
                    errors.push(response_error(&response));
                }
            }
            if error_count > 0 && response.get("type").and_then(Value::as_str) == Some("done") {
                response["had_errors"] = json!(true);
            }
            if response.get("type").and_then(Value::as_str) == Some("cwd")
                && let Some(path) = response.get("path").and_then(Value::as_str)
            {
                self.cwd = path.to_owned();
            }
            if response.get("type").and_then(Value::as_str) != Some("error") {
                render_response(&response, output);
            }
            let event_type = response
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if event_type == "done" || event_type == "cancelled" {
                if error_count > 0 {
                    let omitted = error_count - errors.len();
                    if omitted > 0 {
                        errors.push(format!("and {omitted} more errors"));
                    }
                    bail!("{}", errors.join("\n"));
                }
                if response.get("ok").and_then(Value::as_bool) == Some(false) {
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
                render_response(&response, OutputKind::Other);
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
            render_response(&response, OutputKind::Other);
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
        let mut progress = TransferProgress::new("upload", size);
        while remaining > 0 {
            let length =
                usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
            let read = source.read(&mut buffer[..length]).await?;
            if read == 0 {
                bail!("local upload source changed before all declared bytes were read");
            }
            self.writer.write_all(&buffer[..read]).await?;
            remaining -= read as u64;
            progress.advance(read as u64);
        }
        self.writer.flush().await?;
        self.read_stream(&id, false, OutputKind::Transfer).await?;
        print_transfer_done("Uploaded", &display_local_path(local), remote, size);
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
        let mut progress = TransferProgress::new("download", size);
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
                progress.advance(length as u64);
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
                || response.get("ok").and_then(Value::as_bool) == Some(false)
            {
                bail!("server did not finish the download cleanly");
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if transfer_result.is_err() {
            let _ = fs::remove_file(&temporary).await;
        }
        transfer_result?;
        print_transfer_done("Downloaded", remote, &display_local_path(local), size);
        Ok(())
    }
}

const PROGRESS_BAR_WIDTH: usize = 24;

struct TransferProgress {
    direction: &'static str,
    total: u64,
    transferred: u64,
    last_draw: Instant,
    line_open: bool,
    interactive: bool,
}

impl TransferProgress {
    fn new(direction: &'static str, total: u64) -> Self {
        let mut progress = Self {
            direction,
            total,
            transferred: 0,
            last_draw: Instant::now(),
            line_open: false,
            interactive: std::io::stderr().is_terminal(),
        };
        if progress.interactive {
            progress.draw();
        }
        progress
    }

    fn advance(&mut self, bytes: u64) {
        self.transferred = self.transferred.saturating_add(bytes).min(self.total);
        if self.interactive
            && (self.transferred == self.total || self.last_draw.elapsed().as_millis() >= 100)
        {
            self.draw();
        }
    }

    fn draw(&mut self) {
        let filled = if self.total == 0 {
            PROGRESS_BAR_WIDTH
        } else {
            ((u128::from(self.transferred) * PROGRESS_BAR_WIDTH as u128) / u128::from(self.total))
                as usize
        };
        let percent = if self.total == 0 {
            100.0
        } else {
            self.transferred as f64 / self.total as f64 * 100.0
        };
        let bar = format!(
            "{}{}",
            "#".repeat(filled),
            "-".repeat(PROGRESS_BAR_WIDTH - filled)
        );
        let mut stderr = std::io::stderr().lock();
        self.line_open = true;
        let _ = write!(
            stderr,
            "\r{} [{bar}] {:3.0}% {} / {}",
            self.direction,
            percent,
            format_bytes(self.transferred),
            format_bytes(self.total)
        );
        if self.transferred == self.total {
            let _ = writeln!(stderr);
            self.line_open = false;
        }
        let _ = stderr.flush();
        self.last_draw = Instant::now();
    }
}

impl Drop for TransferProgress {
    fn drop(&mut self) {
        if self.line_open {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr);
            let _ = stderr.flush();
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn resolve_local_path(cwd: &Path, path: Option<&Path>) -> PathBuf {
    match path {
        None => cwd.to_path_buf(),
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => cwd.join(path),
    }
}

fn display_local_path(path: &Path) -> String {
    let displayed = path.display().to_string();
    #[cfg(windows)]
    {
        if let Some(unc) = displayed.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{unc}");
        }
        if let Some(drive) = displayed.strip_prefix(r"\\?\") {
            return drive.to_owned();
        }
    }
    displayed
}

async fn change_local_directory(cwd: &Path, path: &Path) -> anyhow::Result<PathBuf> {
    let target = resolve_local_path(cwd, Some(path));
    let target = fs::canonicalize(&target)
        .await
        .with_context(|| format!("cannot open local directory {}", target.display()))?;
    if !fs::metadata(&target).await?.is_dir() {
        bail!("not a local directory: {}", target.display());
    }
    Ok(target)
}

async fn list_local_directory(directory: &Path) -> anyhow::Result<()> {
    let mut reader = fs::read_dir(directory)
        .await
        .with_context(|| format!("cannot list local directory {}", directory.display()))?;
    let mut entries = Vec::new();
    while let Some(entry) = reader.next_entry().await? {
        entries.push(entry);
    }
    entries.sort_by_key(|entry| entry.file_name());

    print_listing_header(&format!("(local) {}", display_local_path(directory)), false);
    let mut count = 0_u64;
    for entry in &entries {
        let metadata = match fs::symlink_metadata(entry.path()).await {
            Ok(metadata) => metadata,
            Err(error) => {
                eprintln!(
                    "{}: cannot read {}: {error}",
                    paint("warning", "33", true),
                    display_local_path(&entry.path())
                );
                continue;
            }
        };
        let kind = if metadata.file_type().is_symlink() {
            "symlink"
        } else if metadata.is_dir() {
            "directory"
        } else if metadata.is_file() {
            "file"
        } else {
            "other"
        };
        print_listing_row(
            kind,
            Some(metadata.len()),
            &entry.file_name().to_string_lossy(),
        );
        count += 1;
    }
    print_item_count(count);
    Ok(())
}

fn terminal_supports_color(
    is_terminal: bool,
    no_color: bool,
    clicolor: Option<&str>,
    term: Option<&str>,
    windows_ansi: bool,
) -> bool {
    is_terminal && !no_color && clicolor != Some("0") && term != Some("dumb") && windows_ansi
}

fn color_enabled(stderr: bool) -> bool {
    static STDOUT_COLOR: OnceLock<bool> = OnceLock::new();
    static STDERR_COLOR: OnceLock<bool> = OnceLock::new();
    *if stderr { &STDERR_COLOR } else { &STDOUT_COLOR }.get_or_init(|| detect_color(stderr))
}

fn detect_color(stderr: bool) -> bool {
    let is_terminal = if stderr {
        std::io::stderr().is_terminal()
    } else {
        std::io::stdout().is_terminal()
    };
    let clicolor = std::env::var("CLICOLOR").ok();
    let term = std::env::var("TERM").ok();
    // Be conservative on Windows consoles where ANSI support is unknown.
    let windows_ansi = !cfg!(windows)
        || std::env::var_os("WT_SESSION").is_some()
        || std::env::var_os("ANSICON").is_some()
        || std::env::var("ConEmuANSI").is_ok_and(|value| value == "ON")
        || std::env::var_os("TERM_PROGRAM").is_some()
        || term.as_deref().is_some_and(|value| value != "dumb");
    terminal_supports_color(
        is_terminal,
        std::env::var_os("NO_COLOR").is_some(),
        clicolor.as_deref(),
        term.as_deref(),
        windows_ansi,
    )
}

struct CommandHelp {
    name: &'static str,
    usage: &'static str,
    description: &'static str,
}

const FILE_COMMANDS: &[CommandHelp] = &[
    CommandHelp {
        name: "list",
        usage: "list [path]",
        description: "List a remote directory",
    },
    CommandHelp {
        name: "search",
        usage: "search <text> [path]",
        description: "Find names recursively",
    },
    CommandHelp {
        name: "upload",
        usage: "upload <local> <remote>",
        description: "Upload a file",
    },
    CommandHelp {
        name: "download",
        usage: "download <remote> <local>",
        description: "Download a file",
    },
];
const NAV_COMMANDS: &[CommandHelp] = &[
    CommandHelp {
        name: "pwd",
        usage: "pwd",
        description: "Show the remote directory",
    },
    CommandHelp {
        name: "cd",
        usage: "cd <path>",
        description: "Change the remote directory",
    },
    CommandHelp {
        name: "mkdir",
        usage: "mkdir <path>",
        description: "Create a remote directory",
    },
];
const LOCAL_COMMANDS: &[CommandHelp] = &[
    CommandHelp {
        name: "lpwd",
        usage: "lpwd",
        description: "Show the local directory",
    },
    CommandHelp {
        name: "lcd",
        usage: "lcd <path>",
        description: "Change the local directory",
    },
    CommandHelp {
        name: "llist",
        usage: "llist [path]",
        description: "List a local directory",
    },
];
const OTHER_COMMANDS: &[CommandHelp] = &[
    CommandHelp {
        name: "rm",
        usage: "rm <glob>",
        description: "Delete matching remote files",
    },
    CommandHelp {
        name: "help",
        usage: "help [command]",
        description: "Show command help",
    },
    CommandHelp {
        name: "exit",
        usage: "exit",
        description: "Close the session",
    },
    CommandHelp {
        name: "quit",
        usage: "quit",
        description: "Close the session",
    },
];

#[cfg(windows)]
fn split_interactive_command(line: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut in_word = false;
    for character in line.chars() {
        match (quote, character) {
            (Some(delimiter), character) if character == delimiter => quote = None,
            (Some(_), character) => current.push(character),
            (None, '"' | '\'') => {
                quote = Some(character);
                in_word = true;
            }
            (None, character) if character.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut current));
                    in_word = false;
                }
            }
            (None, character) => {
                current.push(character);
                in_word = true;
            }
        }
    }
    if quote.is_some() {
        return Err("unterminated quoted argument".to_owned());
    }
    if in_word {
        words.push(current);
    }
    Ok(words)
}

#[cfg(not(windows))]
fn split_interactive_command(line: &str) -> Result<Vec<String>, String> {
    shell_words::split(line).map_err(|error| error.to_string())
}

fn command_help(name: &str) -> Option<&'static CommandHelp> {
    FILE_COMMANDS
        .iter()
        .chain(NAV_COMMANDS)
        .chain(LOCAL_COMMANDS)
        .chain(OTHER_COMMANDS)
        .find(|item| item.name == name)
}

fn print_help(command: Option<&str>) {
    if let Some(command) = command {
        if let Some(item) = command_help(command) {
            println!(
                "\n{}\n  {}\n  {}\n",
                paint("Usage", "1", false),
                item.usage,
                item.description
            );
        } else {
            print_command_error(command);
        }
        return;
    }
    println!("\n{}", paint("Remote files", "1", false));
    for item in FILE_COMMANDS {
        println!("  {:<27} {}", item.usage, item.description);
    }
    println!("\n{}", paint("Remote navigation", "1", false));
    for item in NAV_COMMANDS {
        println!("  {:<27} {}", item.usage, item.description);
    }
    println!("\n{}", paint("Local", "1", false));
    for item in LOCAL_COMMANDS {
        println!("  {:<27} {}", item.usage, item.description);
    }
    println!("\n{}", paint("Other", "1", false));
    for item in OTHER_COMMANDS {
        println!("  {:<27} {}", item.usage, item.description);
    }
    println!(
        "\nUse help <command> for syntax. Relative local paths use lcd. Quote paths containing spaces.\n"
    );
}

fn suggested_command(command: &str) -> Option<&'static str> {
    FILE_COMMANDS
        .iter()
        .chain(NAV_COMMANDS)
        .chain(LOCAL_COMMANDS)
        .chain(OTHER_COMMANDS)
        .find(|item| item.name.starts_with(command) && command.len() >= 2)
        .map(|item| item.name)
}

fn print_command_error(command: &str) {
    if let Some(item) = command_help(command) {
        eprintln!("{}: usage: {}", paint("error", "31", true), item.usage);
    } else if let Some(suggestion) = suggested_command(command) {
        eprintln!(
            "{}: unknown command {command:?}. Did you mean {suggestion:?}?",
            paint("error", "31", true)
        );
    } else {
        eprintln!(
            "{}: unknown command {command:?}. Type help for commands.",
            paint("error", "31", true)
        );
    }
}

fn paint(text: &str, code: &str, stderr: bool) -> String {
    if color_enabled(stderr) {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

fn print_listing_header(label: &str, search: bool) {
    if search {
        println!("\n{} {}", paint("Search results for", "1", false), label);
        println!("{}", paint("TYPE       PATH", "2", false));
    } else {
        println!("\n{} {}", paint("Listing", "1", false), label);
        let columns = format!("{:<10} {:>9}  {}", "TYPE", "SIZE", "NAME");
        println!("{}", paint(&columns, "2", false));
    }
}

fn print_listing_row(kind: &str, size: Option<u64>, name: &str) {
    let size = if kind == "file" {
        size.map(format_bytes).unwrap_or_else(|| "-".to_owned())
    } else {
        "-".to_owned()
    };
    println!("{kind:<10} {size:>9}  {}", paint(name, "36", false));
}

fn print_item_count(count: u64) {
    let noun = if count == 1 { "item" } else { "items" };
    println!("{} {count} {noun}\n", paint("--", "2", false));
}

fn print_transfer_done(verb: &str, source: &str, destination: &str, size: u64) {
    println!(
        "{} {verb} {source} -> {destination} ({})",
        paint("[ok]", "32", false),
        format_bytes(size)
    );
}

fn response_error(response: &Value) -> String {
    let message = response
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("remote error");
    match response.get("file").and_then(Value::as_str) {
        Some(file) if !file.is_empty() => format!("{message} ({file})"),
        _ => message.to_owned(),
    }
}

fn render_response(response: &Value, output: OutputKind) {
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
            let name = response.get("name").and_then(Value::as_str).unwrap_or(path);
            if matches!(output, OutputKind::Search) {
                println!("{kind:<10} {}", paint(path, "36", false));
            } else {
                print_listing_row(kind, response.get("size").and_then(Value::as_u64), name);
            }
        }
        "deleting" => println!("Deleting {file}"),
        "ready" => {}
        "cwd" => println!("{path}"),
        "accepted" => println!(
            "{} {}",
            paint("[info]", "36", false),
            response
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("accepted")
        ),
        "done" => {
            if let Some(count) = response.get("count").and_then(Value::as_u64) {
                print_item_count(count);
            }
            if let Some(deleted) = response.get("deleted").and_then(Value::as_u64) {
                let noun = if deleted == 1 { "item" } else { "items" };
                let partial = response.get("had_errors").and_then(Value::as_bool) == Some(true)
                    || response.get("ok").and_then(Value::as_bool) == Some(false);
                let (label, color) = if partial {
                    ("[partial]", "33")
                } else {
                    ("[ok]", "32")
                };
                println!("{} Deleted {deleted} {noun}", paint(label, color, false));
            }
            if matches!(output, OutputKind::Other) && !path.is_empty() {
                println!("{} Created directory {path}", paint("[ok]", "32", false));
            }
        }
        "cancelled" => {
            let deleted = response
                .get("deleted")
                .and_then(Value::as_u64)
                .unwrap_or_default();
            let noun = if deleted == 1 { "item" } else { "items" };
            println!("Delete cancelled after {deleted} {noun}");
        }
        "warning" => {
            let message = response
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown issue");
            let affected = if !file.is_empty() { file } else { path };
            let detail = if affected.is_empty() {
                String::new()
            } else {
                format!(" ({affected})")
            };
            eprintln!("{}: {message}{detail}", paint("warning", "33", true));
        }
        "error" => eprintln!(
            "{}: {}",
            paint("error", "31", true),
            response_error(response)
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
    let local_cwd = std::env::current_dir().context("cannot determine local directory")?;
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
        local_cwd,
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
    println!("Connected. Remote directory: {}", session.cwd);
    println!(
        "Local directory: {}",
        display_local_path(&session.local_cwd)
    );
    println!("Type help for commands. Ctrl+C cancels rm; exit closes the session.\n");
    loop {
        print!(
            "{}:{}> ",
            paint("jftp", "1", false),
            paint(&session.cwd, "36", false)
        );
        use std::io::Write;
        std::io::stdout().flush()?;
        let mut line = String::new();
        if input.read_line(&mut line).await? == 0 {
            break;
        }
        // Strip CRLF before tokenizing so the final command has no trailing CR.
        let command_line = line.trim_end_matches(['\r', '\n']);
        let words = match split_interactive_command(command_line) {
            Ok(words) => words,
            Err(error) => {
                eprintln!("{}: {error}", paint("error", "31", true));
                continue;
            }
        };
        let Some(command) = words.first().map(String::as_str) else {
            continue;
        };
        if (command == "exit" || command == "quit") && words.len() == 1 {
            break;
        }
        if command == "help" {
            if words.len() <= 2 {
                print_help(words.get(1).map(String::as_str));
            } else {
                print_command_error(command);
            }
            continue;
        }
        let parsed = match command {
            "list" if words.len() <= 2 => Some(ClientCommand::List {
                path: words.get(1).cloned(),
            }),
            "llist" if words.len() <= 2 => Some(ClientCommand::LocalList {
                path: words.get(1).map(PathBuf::from),
            }),
            "search" if (2..=3).contains(&words.len()) => Some(ClientCommand::Search {
                query: words[1].clone(),
                path: words.get(2).cloned(),
            }),
            "pwd" if words.len() == 1 => Some(ClientCommand::Pwd),
            "lpwd" if words.len() == 1 => Some(ClientCommand::LocalPwd),
            "cd" if words.len() == 2 => Some(ClientCommand::Cd {
                path: words[1].clone(),
            }),
            "lcd" if words.len() == 2 => Some(ClientCommand::LocalCd {
                path: PathBuf::from(&words[1]),
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
                    eprintln!("{}: {error:#}", paint("error", "31", true));
                }
            }
            None => print_command_error(command),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn color_falls_back_for_non_terminal_and_disabled_environments() {
        assert!(!terminal_supports_color(false, false, None, None, true));
        assert!(!terminal_supports_color(true, true, None, None, true));
        assert!(!terminal_supports_color(true, false, Some("0"), None, true));
        assert!(!terminal_supports_color(
            true,
            false,
            None,
            Some("dumb"),
            true
        ));
        assert!(!terminal_supports_color(true, false, None, None, false));
        assert!(terminal_supports_color(true, false, None, None, true));
    }

    #[test]
    fn command_feedback_uses_specific_syntax_and_suggestions() {
        assert_eq!(
            command_help("download").unwrap().usage,
            "download <remote> <local>"
        );
        assert_eq!(suggested_command("lis"), Some("list"));
        assert_eq!(suggested_command("unknown"), None);
    }

    #[test]
    fn remote_errors_keep_the_affected_file() {
        let response = json!({"type":"error", "message":"permission denied", "file":"/report.txt"});
        assert_eq!(response_error(&response), "permission denied (/report.txt)");
    }

    #[tokio::test]
    async fn local_directory_changes_validate_the_target() {
        let cwd = std::env::current_dir().unwrap();
        let selected = change_local_directory(&cwd, Path::new(".")).await.unwrap();
        assert_eq!(selected, fs::canonicalize(&cwd).await.unwrap());
        assert!(
            change_local_directory(&cwd, &std::env::current_exe().unwrap())
                .await
                .is_err()
        );
        assert_eq!(
            resolve_local_path(&selected, Some(Path::new("report.txt"))),
            selected.join("report.txt")
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_paths_keep_backslashes_in_interactive_commands() {
        assert_eq!(
            split_interactive_command(r"lcd C:\tmp\files").unwrap(),
            ["lcd", r"C:\tmp\files"]
        );
        assert_eq!(
            split_interactive_command(r#"llist "C:\My Files""#).unwrap(),
            ["llist", r"C:\My Files"]
        );
        assert_eq!(display_local_path(Path::new(r"\\?\C:\tmp")), r"C:\tmp");
        assert_eq!(
            display_local_path(Path::new(r"\\?\UNC\server\share")),
            r"\\server\share"
        );
    }
}
