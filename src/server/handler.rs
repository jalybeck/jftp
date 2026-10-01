use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context, bail};
use glob::Pattern;
use russh::{
    Channel, ChannelId, ChannelOpenFailure,
    keys::ssh_key::PublicKey,
    server::{self, Auth, Handle, Handler, Session},
};
use serde_json::{Value, json};
use tokio::{
    fs::{self, File, OpenOptions},
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    path_security::PathSecurity,
    protocol::{MAX_JSON_LINE, Request, SUBSYSTEM_NAME, TRANSFER_CHUNK_SIZE},
};

use super::{ServerContext, UserAccount};

struct SessionState {
    account: Option<UserAccount>,
    home_directory: Option<PathBuf>,
    current_working_directory: Option<PathBuf>,
    channel: Option<ChannelId>,
    subsystem_ready: bool,
    input_line: Vec<u8>,
    discard_json_line: bool,
    upload: Option<UploadState>,
    deletion: Option<DeletionJob>,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            account: None,
            home_directory: None,
            current_working_directory: None,
            channel: None,
            subsystem_ready: false,
            input_line: Vec::new(),
            discard_json_line: false,
            upload: None,
            deletion: None,
        }
    }
}

struct UploadState {
    id: String,
    size: u64,
    remaining: u64,
    temporary_path: PathBuf,
    destination: PathBuf,
    file: File,
}

struct DeletionJob {
    id: String,
    cancellation: CancellationToken,
    finished: Arc<AtomicBool>,
}

pub struct JftpHandler {
    context: Arc<ServerContext>,
    state: SessionState,
}

impl JftpHandler {
    pub(super) fn new(context: Arc<ServerContext>) -> Self {
        Self {
            context,
            state: SessionState::default(),
        }
    }

    fn paths(&self) -> anyhow::Result<PathSecurity> {
        self.state
            .home_directory
            .clone()
            .map(PathSecurity::new)
            .context("the session is not authenticated")
    }

    fn cwd(&self) -> anyhow::Result<&Path> {
        self.state
            .current_working_directory
            .as_deref()
            .context("the session is not authenticated")
    }

    fn account(&self) -> anyhow::Result<&UserAccount> {
        self.state
            .account
            .as_ref()
            .context("the session is not authenticated")
    }

    async fn send_json(handle: &Handle, channel: ChannelId, value: &Value) -> anyhow::Result<()> {
        let mut bytes = serde_json::to_vec(value)?;
        bytes.push(b'\n');
        handle
            .data(channel, bytes)
            .await
            .map_err(|_| anyhow::anyhow!("SSH channel closed while sending response"))
    }

    async fn send_error(
        handle: &Handle,
        channel: ChannelId,
        id: &str,
        message: impl AsRef<str>,
    ) -> anyhow::Result<()> {
        Self::send_json(
            handle,
            channel,
            &json!({"type":"error", "id":id, "message":message.as_ref()}),
        )
        .await
    }

    async fn dispatch(
        &mut self,
        handle: &Handle,
        channel: ChannelId,
        request: Request,
    ) -> anyhow::Result<()> {
        let id = request.id.as_str();
        match request.command.as_str() {
            "pwd" => {
                let cwd = self.cwd()?;
                let display = self.paths()?.display(cwd);
                Self::send_json(
                    handle,
                    channel,
                    &json!({"type":"cwd", "id":id, "path":display}),
                )
                .await?;
                Self::send_json(handle, channel, &json!({"type":"done", "id":id})).await?;
            }
            "cd" => {
                let account = self.account()?;
                if !account.can_read {
                    bail!("this account does not have read permission");
                }
                let path = request.path.as_deref().context("cd requires a path")?;
                let paths = self.paths()?;
                let resolved = paths.resolve_existing(self.cwd()?, path).await?;
                if !fs::metadata(&resolved).await?.is_dir() {
                    bail!("not a directory: {path}");
                }
                self.state.current_working_directory = Some(resolved.clone());
                Self::send_json(
                    handle,
                    channel,
                    &json!({"type":"cwd", "id":id, "path":paths.display(&resolved)}),
                )
                .await?;
                Self::send_json(handle, channel, &json!({"type":"done", "id":id})).await?;
            }
            "list" => self.list(handle, channel, &request).await?,
            "search" => self.search(handle, channel, &request).await?,
            "mkdir" => self.mkdir(handle, channel, &request).await?,
            "rm" => self.start_delete(handle, channel, request).await?,
            "cancel" => self.cancel_delete(handle, channel, &request).await?,
            "download" => self.download(handle, channel, &request).await?,
            "upload" => self.start_upload(handle, channel, &request).await?,
            unknown => bail!("unknown command: {unknown}"),
        }
        Ok(())
    }

    async fn list(
        &self,
        handle: &Handle,
        channel: ChannelId,
        request: &Request,
    ) -> anyhow::Result<()> {
        let account = self.account()?;
        if !account.can_read {
            bail!("this account does not have read permission");
        }
        let paths = self.paths()?;
        let input = request.path.as_deref().unwrap_or(".");
        let directory = paths.resolve_existing(self.cwd()?, input).await?;
        if !fs::metadata(&directory).await?.is_dir() {
            bail!("not a directory: {input}");
        }

        let mut entries = fs::read_dir(&directory)
            .await
            .with_context(|| format!("cannot list {}", paths.display(&directory)))?;
        let mut count = 0_u64;
        while let Some(entry) = entries.next_entry().await? {
            let metadata = match fs::symlink_metadata(entry.path()).await {
                Ok(metadata) => metadata,
                Err(error) => {
                    Self::send_json(handle, channel, &json!({"type":"warning", "id":request.id, "file":entry.file_name().to_string_lossy(), "message":error.to_string()})).await?;
                    continue;
                }
            };
            let file_type = metadata.file_type();
            let kind = if file_type.is_symlink() {
                "symlink"
            } else if file_type.is_dir() {
                "directory"
            } else if file_type.is_file() {
                "file"
            } else {
                "other"
            };
            Self::send_json(
                handle,
                channel,
                &json!({
                    "type":"entry", "id":request.id,
                    "name":entry.file_name().to_string_lossy(),
                    "path":paths.display(&entry.path()), "kind":kind,
                    "size":metadata.len()
                }),
            )
            .await?;
            count += 1;
        }
        Self::send_json(
            handle,
            channel,
            &json!({"type":"done", "id":request.id, "count":count}),
        )
        .await?;
        Ok(())
    }

    async fn search(
        &self,
        handle: &Handle,
        channel: ChannelId,
        request: &Request,
    ) -> anyhow::Result<()> {
        let account = self.account()?;
        if !account.can_read {
            bail!("this account does not have read permission");
        }
        let query = request
            .query
            .as_deref()
            .context("search requires a query")?
            .trim();
        if query.is_empty() {
            bail!("search query must not be empty");
        }
        let paths = self.paths()?;
        let start = paths
            .resolve_existing(self.cwd()?, request.path.as_deref().unwrap_or("."))
            .await?;
        if !fs::metadata(&start).await?.is_dir() {
            bail!("search start path is not a directory");
        }

        let query = query.to_lowercase();
        let mut pending = VecDeque::from([(start, 0_usize)]);
        let mut count = 0_u64;
        while let Some((directory, depth)) = pending.pop_front() {
            let mut entries = match fs::read_dir(&directory).await {
                Ok(entries) => entries,
                Err(error) => {
                    Self::send_json(handle, channel, &json!({"type":"warning", "id":request.id, "path":paths.display(&directory), "message":error.to_string()})).await?;
                    continue;
                }
            };
            while let Some(entry) = entries.next_entry().await? {
                let file_type = match entry.file_type().await {
                    Ok(file_type) => file_type,
                    Err(error) => {
                        Self::send_json(handle, channel, &json!({"type":"warning", "id":request.id, "path":paths.display(&entry.path()), "message":error.to_string()})).await?;
                        continue;
                    }
                };
                let name = entry.file_name().to_string_lossy().into_owned();
                let is_dir = file_type.is_dir();
                if name.to_lowercase().contains(&query) {
                    Self::send_json(handle, channel, &json!({"type":"entry", "id":request.id, "name":name, "path":paths.display(&entry.path()), "kind":if is_dir {"directory"} else if file_type.is_symlink() {"symlink"} else {"file"}})).await?;
                    count += 1;
                }
                if is_dir && !file_type.is_symlink() && depth < 64 {
                    let canonical = match fs::canonicalize(entry.path()).await {
                        Ok(canonical) if canonical.starts_with(paths.home()) => canonical,
                        _ => continue,
                    };
                    pending.push_back((canonical, depth + 1));
                }
            }
        }
        Self::send_json(
            handle,
            channel,
            &json!({"type":"done", "id":request.id, "count":count}),
        )
        .await?;
        Ok(())
    }

    async fn mkdir(
        &self,
        handle: &Handle,
        channel: ChannelId,
        request: &Request,
    ) -> anyhow::Result<()> {
        let account = self.account()?;
        if !account.can_write {
            bail!("this account does not have write permission");
        }
        let input = request.path.as_deref().context("mkdir requires a path")?;
        let paths = self.paths()?;
        let (parent, destination) = paths.resolve_new_file(self.cwd()?, input).await?;
        // `resolve_new_file` validates a leaf and an existing parent; mkdir
        // creates the leaf as a directory instead of a regular file.
        let _ = parent;
        fs::create_dir(&destination)
            .await
            .with_context(|| format!("cannot create directory {}", paths.display(&destination)))?;
        Self::send_json(
            handle,
            channel,
            &json!({"type":"done", "id":request.id, "path":paths.display(&destination)}),
        )
        .await?;
        Ok(())
    }

    async fn start_delete(
        &mut self,
        handle: &Handle,
        channel: ChannelId,
        request: Request,
    ) -> anyhow::Result<()> {
        let account = self.account()?;
        if !account.can_delete {
            bail!("this account does not have delete permission");
        }
        if self
            .state
            .deletion
            .as_ref()
            .is_some_and(|job| !job.finished.load(Ordering::Acquire))
        {
            bail!("another delete operation is still running");
        }
        let input = request
            .path
            .as_deref()
            .context("rm requires a path or glob pattern")?;
        let paths = self.paths()?;
        let pattern_text = paths.glob_pattern(self.cwd()?, input)?;
        Pattern::new(&pattern_text).context("invalid glob pattern")?;
        let id = request.id.clone();
        let recursive = request.recursive;
        let cancellation = CancellationToken::new();
        let finished = Arc::new(AtomicBool::new(false));
        self.state.deletion = Some(DeletionJob {
            id: id.clone(),
            cancellation: cancellation.clone(),
            finished: finished.clone(),
        });
        Self::send_json(
            handle,
            channel,
            &json!({"type":"accepted", "id":request.id, "message":"delete operation started"}),
        )
        .await?;

        let (sender, mut receiver) = mpsc::channel::<Result<PathBuf, String>>(128);
        let producer_pattern = pattern_text.clone();
        tokio::task::spawn_blocking(move || match glob::glob(&producer_pattern) {
            Ok(matches) => {
                for matched in matches {
                    let item = matched.map_err(|error| error.to_string());
                    if sender.blocking_send(item).is_err() {
                        break;
                    }
                }
            }
            Err(error) => {
                let _ = sender.blocking_send(Err(error.to_string()));
            }
        });

        let handle = handle.clone();
        let path_guard = paths.clone();
        let home = path_guard.home().to_path_buf();
        tokio::spawn(async move {
            let mut count = 0_u64;
            let mut matched_any = false;
            let mut had_errors = false;
            while let Some(item) = receiver.recv().await {
                if cancellation.is_cancelled() {
                    break;
                }
                let candidate = match item {
                    Ok(candidate) => candidate,
                    Err(message) => {
                        had_errors = true;
                        let _ = JftpHandler::send_error(&handle, channel, &id, message).await;
                        continue;
                    }
                };
                matched_any = true;
                let link_metadata = match fs::symlink_metadata(&candidate).await {
                    Ok(metadata) => metadata,
                    Err(error) => {
                        had_errors = true;
                        let _ = JftpHandler::send_json(&handle, channel, &json!({"type":"error", "id":id, "file":path_guard.display(&candidate), "message":error.to_string()})).await;
                        continue;
                    }
                };
                let target = if link_metadata.file_type().is_symlink() {
                    let parent = match candidate.parent() {
                        Some(parent) => fs::canonicalize(parent).await,
                        None => Err(std::io::Error::other(
                            "delete candidate has no parent directory",
                        )),
                    };
                    match parent {
                        Ok(parent) if parent.starts_with(&home) => candidate.clone(),
                        Ok(_) => {
                            had_errors = true;
                            let _ = JftpHandler::send_error(
                                &handle,
                                channel,
                                &id,
                                "symlink parent escapes this user's home",
                            )
                            .await;
                            continue;
                        }
                        Err(error) => {
                            had_errors = true;
                            let _ =
                                JftpHandler::send_error(&handle, channel, &id, error.to_string())
                                    .await;
                            continue;
                        }
                    }
                } else {
                    match fs::canonicalize(&candidate).await {
                        Ok(target) if target.starts_with(&home) && target != home => target,
                        Ok(_) => {
                            had_errors = true;
                            let _ = JftpHandler::send_error(
                                &handle,
                                channel,
                                &id,
                                "refusing to remove the home directory or a path outside it",
                            )
                            .await;
                            continue;
                        }
                        Err(error) => {
                            had_errors = true;
                            let _ =
                                JftpHandler::send_error(&handle, channel, &id, error.to_string())
                                    .await;
                            continue;
                        }
                    }
                };
                let shown = path_guard.display(&target);
                if JftpHandler::send_json(
                    &handle,
                    channel,
                    &json!({"type":"deleting", "id":id, "file":shown}),
                )
                .await
                .is_err()
                {
                    break;
                }
                let result = if link_metadata.file_type().is_symlink() {
                    #[cfg(windows)]
                    {
                        match fs::remove_file(&candidate).await {
                            Ok(()) => Ok(()),
                            Err(file_error) => fs::remove_dir(&candidate)
                                .await
                                .map_err(|dir_error| anyhow::anyhow!("{file_error}; {dir_error}")),
                        }
                    }
                    #[cfg(not(windows))]
                    {
                        fs::remove_file(&candidate).await.map_err(Into::into)
                    }
                } else if link_metadata.is_dir() {
                    if recursive {
                        fs::remove_dir_all(&target).await.map_err(Into::into)
                    } else {
                        fs::remove_dir(&target).await.map_err(Into::into)
                    }
                } else {
                    fs::remove_file(&target).await.map_err(Into::into)
                };
                match result {
                    Ok(()) => count += 1,
                    Err(error) => {
                        had_errors = true;
                        let _ = JftpHandler::send_json(&handle, channel, &json!({"type":"error", "id":id, "file":shown, "message":error.to_string()})).await;
                    }
                }
            }
            if !matched_any {
                let _ = JftpHandler::send_error(
                    &handle,
                    channel,
                    &id,
                    format!("pattern matched no items: {pattern_text}"),
                )
                .await;
            }
            let event_type = if cancellation.is_cancelled() {
                "cancelled"
            } else {
                "done"
            };
            let _ = JftpHandler::send_json(
                &handle,
                channel,
                &json!({"type":event_type, "id":id, "deleted":count, "had_errors":had_errors}),
            )
            .await;
            finished.store(true, Ordering::Release);
        });
        Ok(())
    }

    async fn cancel_delete(
        &mut self,
        handle: &Handle,
        channel: ChannelId,
        request: &Request,
    ) -> anyhow::Result<()> {
        let target = request.path.as_deref();
        match self.state.deletion.as_ref() {
            Some(job) if !job.finished.load(Ordering::Acquire) && target.is_none_or(|target| target == job.id) => {
                job.cancellation.cancel();
                Self::send_json(handle, channel, &json!({"type":"accepted", "id":request.id, "message":"cancellation requested", "target_id":job.id})).await?;
            }
            _ => Self::send_json(handle, channel, &json!({"type":"error", "id":request.id, "message":"no matching delete operation is running"})).await?,
        }
        Self::send_json(handle, channel, &json!({"type":"done", "id":request.id})).await?;
        Ok(())
    }

    async fn download(
        &self,
        handle: &Handle,
        channel: ChannelId,
        request: &Request,
    ) -> anyhow::Result<()> {
        let account = self.account()?;
        if !account.can_read {
            bail!("this account does not have read permission");
        }
        let input = request
            .path
            .as_deref()
            .context("download requires a path")?;
        let paths = self.paths()?;
        let resolved = paths.resolve_existing(self.cwd()?, input).await?;
        let mut file = File::open(&resolved)
            .await
            .with_context(|| format!("cannot open {}", paths.display(&resolved)))?;
        let metadata = file.metadata().await?;
        if !metadata.is_file() {
            bail!("download source is not a regular file");
        }
        let size = metadata.len();
        let id = request.id.clone();
        let display_path = paths.display(&resolved);
        Self::send_json(
            handle,
            channel,
            &json!({"type":"ready", "id":id, "transfer":"download", "size":size, "path":display_path}),
        )
        .await?;

        // Handler::data runs on russh's session task. Sending the whole file
        // through Handle::data here would fill that same task's bounded
        // message queue and deadlock before it can drain the queued chunks.
        // Stream from a separate task so russh can process window updates and
        // outgoing data concurrently.
        let transfer_handle = handle.clone();
        tokio::spawn(async move {
            let transfer_result = async {
                let mut remaining = size;
                let mut buffer = vec![0_u8; TRANSFER_CHUNK_SIZE];
                while remaining > 0 {
                    let length =
                        usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
                    file.read_exact(&mut buffer[..length])
                        .await
                        .context("download source changed during transfer")?;
                    transfer_handle
                        .data(channel, buffer[..length].to_vec())
                        .await
                        .map_err(|_| anyhow::anyhow!("SSH channel closed during download"))?;
                    remaining -= length as u64;
                }
                Self::send_json(
                    &transfer_handle,
                    channel,
                    &json!({"type":"done", "id":id, "size":size}),
                )
                .await?;
                Ok::<(), anyhow::Error>(())
            }
            .await;

            if let Err(error) = transfer_result {
                eprintln!("download {id} failed: {error:#}; closing SSH channel");
                // Once raw transfer mode has started, sending JSON errors
                // would be interpreted as file bytes by the client. Closing
                // the channel makes its exact-length read fail safely.
                let _ = transfer_handle.close(channel).await;
            }
        });
        Ok(())
    }

    async fn start_upload(
        &mut self,
        handle: &Handle,
        channel: ChannelId,
        request: &Request,
    ) -> anyhow::Result<()> {
        let account = self.account()?;
        if !account.can_write {
            bail!("this account does not have write permission");
        }
        if self.state.upload.is_some() {
            bail!("an upload is already in progress");
        }
        let size = request.size.context("upload requires a size")?;
        let input = request
            .path
            .as_deref()
            .context("upload requires a destination path")?;
        let paths = self.paths()?;
        let (_parent, destination) = paths.resolve_new_file(self.cwd()?, input).await?;
        let leaf = destination
            .file_name()
            .context("destination file name is required")?
            .to_string_lossy();
        let temporary_path =
            destination.with_file_name(format!(".{leaf}.jftp-{}.part", Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .await
            .with_context(|| {
                format!(
                    "cannot create temporary upload file in {}",
                    destination.parent().unwrap_or(Path::new(".")).display()
                )
            })?;
        if size == 0 {
            file.flush().await?;
            drop(file);
            fs::hard_link(&temporary_path, &destination)
                .await
                .with_context(|| {
                    format!(
                        "cannot publish uploaded file {}",
                        paths.display(&destination)
                    )
                })?;
            fs::remove_file(&temporary_path).await?;
            Self::send_json(
                handle,
                channel,
                &json!({"type":"ready", "id":request.id, "transfer":"upload", "size":0}),
            )
            .await?;
            Self::send_json(handle, channel, &json!({"type":"done", "id":request.id, "size":0, "path":paths.display(&destination)})).await?;
            return Ok(());
        }

        self.state.upload = Some(UploadState {
            id: request.id.clone(),
            size,
            remaining: size,
            temporary_path,
            destination,
            file,
        });
        Self::send_json(
            handle,
            channel,
            &json!({"type":"ready", "id":request.id, "transfer":"upload", "size":size}),
        )
        .await?;
        Ok(())
    }

    async fn ingest_upload(
        &mut self,
        handle: &Handle,
        channel: ChannelId,
        bytes: &[u8],
    ) -> anyhow::Result<usize> {
        let Some(upload) = self.state.upload.as_mut() else {
            return Ok(0);
        };
        let count =
            usize::try_from(upload.remaining.min(bytes.len() as u64)).unwrap_or(bytes.len());
        if let Err(error) = upload.file.write_all(&bytes[..count]).await {
            let id = upload.id.clone();
            let temporary = upload.temporary_path.clone();
            self.state.upload = None;
            let _ = fs::remove_file(temporary).await;
            Self::send_error(
                handle,
                channel,
                &id,
                format!("cannot write upload: {error}"),
            )
            .await?;
            bail!("upload failed; closing the session to end raw transfer mode");
        }
        upload.remaining -= count as u64;
        if upload.remaining == 0 {
            let mut upload = self.state.upload.take().expect("upload state was present");
            upload.file.flush().await?;
            drop(upload.file);
            let publish_result = fs::hard_link(&upload.temporary_path, &upload.destination).await;
            if let Err(error) = publish_result {
                let _ = fs::remove_file(&upload.temporary_path).await;
                Self::send_error(
                    handle,
                    channel,
                    &upload.id,
                    format!("cannot publish uploaded file: {error}"),
                )
                .await?;
                Self::send_json(
                    handle,
                    channel,
                    &json!({"type":"done", "id":upload.id, "ok":false}),
                )
                .await?;
            } else {
                fs::remove_file(&upload.temporary_path).await?;
                let display = self.paths()?.display(&upload.destination);
                Self::send_json(
                    handle,
                    channel,
                    &json!({"type":"done", "id":upload.id, "size":upload.size, "path":display}),
                )
                .await?;
            }
        }
        Ok(count)
    }

    async fn process_line(
        &mut self,
        handle: &Handle,
        channel: ChannelId,
        line: &[u8],
    ) -> anyhow::Result<()> {
        let trimmed = line.strip_suffix(b"\r").unwrap_or(line);
        if trimmed.is_empty() {
            return Ok(());
        }
        let request: Request = match serde_json::from_slice(trimmed) {
            Ok(request) => request,
            Err(error) => {
                Self::send_error(
                    handle,
                    channel,
                    "",
                    format!("invalid JSONL command: {error}"),
                )
                .await?;
                return Ok(());
            }
        };
        let id = request.id.clone();
        if request.id.is_empty() {
            Self::send_error(handle, channel, "", "request id must not be empty").await?;
            return Ok(());
        }
        if let Err(error) = self.dispatch(handle, channel, request).await {
            Self::send_error(handle, channel, &id, format!("{error:#}")).await?;
            Self::send_json(
                handle,
                channel,
                &json!({"type":"done", "id":id, "ok":false}),
            )
            .await?;
        }
        Ok(())
    }
}

impl Handler for JftpHandler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::reject())
    }

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::reject())
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        let accepted = self
            .context
            .users
            .get(user)
            .is_some_and(|account| account.authorized_keys.contains(public_key));
        Ok(if accepted {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        let Some(account) = self.context.users.get(user) else {
            return Ok(Auth::reject());
        };
        if !account.authorized_keys.contains(public_key) {
            return Ok(Auth::reject());
        }
        self.state.account = Some(account.clone());
        self.state.home_directory = Some(account.home_directory.clone());
        self.state.current_working_directory = Some(account.home_directory.clone());
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.state.channel.is_some() {
            reply.reject(ChannelOpenFailure::ResourceShortage).await;
        } else {
            self.state.channel = Some(channel.id());
            // This handler consumes channel data in `Handler::data`. Keeping
            // the Channel's separate read queue alive would duplicate every
            // packet into a bounded queue that this callback never drains.
            // Drop the receiver so russh can continue dispatching callbacks.
            drop(channel);
            reply.accept().await;
        }
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.state.account.is_some()
            && self.state.channel == Some(channel)
            && name == SUBSYSTEM_NAME
        {
            self.state.subsystem_ready = true;
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let handle = session.handle();
        if !self.state.subsystem_ready
            || self.state.channel != Some(channel)
            || self.state.account.is_none()
        {
            Self::send_error(
                &handle,
                channel,
                "",
                "request the authenticated jftp subsystem first",
            )
            .await?;
            return Ok(());
        }

        let mut offset = 0;
        while offset < data.len() {
            if self.state.discard_json_line {
                if let Some(newline) = data[offset..].iter().position(|byte| *byte == b'\n') {
                    offset += newline + 1;
                    self.state.discard_json_line = false;
                    continue;
                }
                return Ok(());
            }
            if self.state.upload.is_some() {
                let consumed = self
                    .ingest_upload(&handle, channel, &data[offset..])
                    .await?;
                if consumed == 0 {
                    break;
                }
                offset += consumed;
                continue;
            }

            if let Some(newline) = data[offset..].iter().position(|byte| *byte == b'\n') {
                let end = offset + newline;
                if self.state.input_line.len() + newline > MAX_JSON_LINE {
                    self.state.input_line.clear();
                    Self::send_error(
                        &handle,
                        channel,
                        "",
                        "JSONL command exceeds the 1 MiB limit",
                    )
                    .await?;
                } else {
                    self.state.input_line.extend_from_slice(&data[offset..end]);
                    let line = std::mem::take(&mut self.state.input_line);
                    self.process_line(&handle, channel, &line).await?;
                }
                offset = end + 1;
            } else {
                let remaining = &data[offset..];
                if self.state.input_line.len() + remaining.len() > MAX_JSON_LINE {
                    self.state.input_line.clear();
                    self.state.discard_json_line = true;
                    Self::send_error(
                        &handle,
                        channel,
                        "",
                        "JSONL command exceeds the 1 MiB limit",
                    )
                    .await?;
                } else {
                    self.state.input_line.extend_from_slice(remaining);
                }
                break;
            }
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.state.channel == Some(channel) {
            self.state.channel = None;
            self.state.subsystem_ready = false;
            if let Some(job) = &self.state.deletion {
                job.cancellation.cancel();
            }
            if let Some(upload) = self.state.upload.take() {
                let _ = fs::remove_file(upload.temporary_path).await;
            }
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.state.channel == Some(channel) {
            if let Some(job) = &self.state.deletion {
                job.cancellation.cancel();
            }
            if let Some(upload) = self.state.upload.take() {
                let _ = fs::remove_file(upload.temporary_path).await;
                return Err(anyhow::anyhow!("connection ended during upload"));
            }
        }
        Ok(())
    }
}
