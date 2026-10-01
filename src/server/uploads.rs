use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use sha2::{Digest, Sha256};
use tokio::{
    fs::{self, File, OpenOptions},
    io::AsyncWriteExt,
    sync::Mutex,
};
use uuid::Uuid;

use crate::transfer::{checksum, validate_checksum};

const RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_TRANSFERS: usize = 1024;

#[derive(Debug, Default)]
pub(super) struct UploadStore {
    records: Mutex<HashMap<Uuid, Arc<Mutex<Record>>>>,
}

#[derive(Debug)]
struct Record {
    user: String,
    destination: PathBuf,
    temporary: PathBuf,
    size: u64,
    checksum: String,
    received: u64,
    hash: Sha256,
    file: Option<File>,
    completed: bool,
    failed: bool,
    generation: Uuid,
    touched: Instant,
}

pub(super) struct UploadLease {
    record: Arc<Mutex<Record>>,
    generation: Uuid,
    pub id: String,
    pub size: u64,
    pub remaining: u64,
}

impl UploadStore {
    pub async fn acknowledge(&self, token: &str, user: &str) -> anyhow::Result<()> {
        let token = Uuid::parse_str(token).context("invalid upload transfer ID")?;
        let mut records = self.records.lock().await;
        if let Some(record) = records.get(&token) {
            let state = record.lock().await;
            if state.user != user || !state.completed {
                bail!("only the owner can acknowledge a completed upload");
            }
            drop(state);
            records.remove(&token);
        }
        Ok(())
    }

    pub async fn begin(
        &self,
        token: &str,
        user: &str,
        destination: PathBuf,
        size: u64,
        expected_checksum: Option<&str>,
        request_id: &str,
    ) -> anyhow::Result<(UploadLease, u64, bool)> {
        let token = Uuid::parse_str(token).context("invalid upload transfer ID")?;
        let expected_checksum = validate_checksum(expected_checksum)?;
        let mut records = self.records.lock().await;
        // Bound retained sessions. Expired partial files are removed the next
        // time a transfer starts; active transfers refresh their timestamp.
        records.retain(|_, record| {
            if let Ok(mut record) = record.try_lock()
                && record.touched.elapsed() > RETENTION
            {
                record.file.take();
                let temporary = record.temporary.clone();
                tokio::spawn(async move {
                    let _ = fs::remove_file(temporary).await;
                });
                return false;
            }
            true
        });
        let record = if let Some(record) = records.get(&token) {
            record.clone()
        } else {
            if records.len() >= MAX_TRANSFERS {
                bail!("too many retained uploads; try again later");
            }
            if fs::try_exists(&destination).await? {
                bail!("destination already exists");
            }
            let temporary = destination.with_file_name(format!(".jftp-upload-{token}.part"));
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .await
                .context("cannot create resumable upload file")?;
            let record = Arc::new(Mutex::new(Record {
                user: user.to_owned(),
                destination: destination.clone(),
                temporary,
                size,
                checksum: expected_checksum.to_owned(),
                received: 0,
                hash: Sha256::new(),
                file: Some(file),
                completed: false,
                failed: false,
                generation: Uuid::new_v4(),
                touched: Instant::now(),
            }));
            records.insert(token, record.clone());
            record
        };
        drop(records);
        let mut state = record.lock().await;
        if state.user != user
            || state.destination != destination
            || state.size != size
            || state.checksum != expected_checksum
        {
            bail!("upload transfer ID does not match this user, destination or source file");
        }
        if state.failed {
            bail!("previous upload failed validation; start a new transfer");
        }
        if state.completed {
            let mut file = File::open(&state.destination).await?;
            if file.metadata().await?.len() != size
                || checksum(&mut file).await? != expected_checksum
            {
                bail!("completed upload destination has changed");
            }
        } else if state.received == size {
            state.finish().await?;
        }
        // A new SSH session takes ownership. Late bytes from the old session
        // are rejected instead of appending them a second time.
        state.generation = Uuid::new_v4();
        state.touched = Instant::now();
        let generation = state.generation;
        let offset = state.received;
        let completed = state.completed;
        drop(state);
        Ok((
            UploadLease {
                record,
                generation,
                id: request_id.to_owned(),
                size,
                remaining: size - offset,
            },
            offset,
            completed,
        ))
    }
}

impl UploadLease {
    pub async fn write(&mut self, bytes: &[u8]) -> anyhow::Result<usize> {
        let mut record = self.record.lock().await;
        if record.generation != self.generation {
            bail!("upload resumed in another SSH session");
        }
        let count = usize::try_from(self.remaining.min(bytes.len() as u64)).unwrap_or(bytes.len());
        let write_result = record
            .file
            .as_mut()
            .context("upload file is closed")?
            .write_all(&bytes[..count])
            .await;
        if let Err(error) = write_result {
            record.failed = true;
            record.file.take();
            let _ = fs::remove_file(&record.temporary).await;
            return Err(error.into());
        }
        record.hash.update(&bytes[..count]);
        record.received += count as u64;
        self.remaining -= count as u64;
        record.touched = Instant::now();
        if self.remaining == 0 {
            record.finish().await?;
        }
        Ok(count)
    }
}

impl Record {
    async fn finish(&mut self) -> anyhow::Result<()> {
        if crate::transfer::hex_digest(&self.hash.clone().finalize()) != self.checksum {
            self.failed = true;
            self.file.take();
            let _ = fs::remove_file(&self.temporary).await;
            bail!("upload SHA-256 checksum mismatch; destination was not published");
        }
        let file = self.file.as_mut().context("upload file is closed")?;
        file.flush().await?;
        file.sync_all().await?;
        fs::hard_link(&self.temporary, &self.destination)
            .await
            .context("cannot publish upload; destination may already exist")?;
        self.completed = true;
        self.file.take();
        let _ = fs::remove_file(&self.temporary).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        directory: PathBuf,
        destination: PathBuf,
        token: String,
        checksum: String,
        store: UploadStore,
    }

    impl Fixture {
        async fn new() -> Self {
            let directory =
                std::env::temp_dir().join(format!("jftp-upload-test-{}", Uuid::new_v4()));
            fs::create_dir(&directory).await.unwrap();
            Self {
                destination: directory.join("file.bin"),
                directory,
                token: Uuid::new_v4().to_string(),
                checksum: crate::transfer::hex_digest(&Sha256::digest(b"abcdef")),
                store: Default::default(),
            }
        }

        async fn begin(&self) -> (UploadLease, u64, bool) {
            self.store
                .begin(
                    &self.token,
                    "alice",
                    self.destination.clone(),
                    6,
                    Some(&self.checksum),
                    "request",
                )
                .await
                .unwrap()
        }

        async fn cleanup(self) {
            let directory = self.directory.clone();
            drop(self);
            fs::remove_dir_all(directory).await.unwrap();
        }
    }

    #[tokio::test]
    async fn resume_replaces_old_writer_and_recovers_lost_completion_ack() {
        let fixture = Fixture::new().await;
        let (mut old, offset, complete) = fixture.begin().await;
        assert_eq!(offset, 0);
        assert!(!complete);
        old.write(b"abc").await.unwrap();
        let (mut resumed, offset, complete) = fixture.begin().await;
        assert_eq!(offset, 3);
        assert!(!complete);
        assert!(old.write(b"def").await.is_err());
        resumed.write(b"def").await.unwrap();
        // Simulate losing done: another session must recognize completion,
        // rather than rejecting the now-existing destination or uploading twice.
        let (completed, offset, complete) = fixture.begin().await;
        assert_eq!(offset, 6);
        assert!(complete);
        assert_eq!(fs::read(&fixture.destination).await.unwrap(), b"abcdef");
        fixture
            .store
            .acknowledge(&fixture.token, "alice")
            .await
            .unwrap();
        assert!(fixture.store.records.lock().await.is_empty());
        drop((old, resumed, completed));
        fixture.cleanup().await;
    }

    #[tokio::test]
    async fn resume_rejects_other_user_destination_and_changed_source() {
        let fixture = Fixture::new().await;
        let (mut upload, _, _) = fixture.begin().await;
        upload.write(b"abc").await.unwrap();
        for (user, destination, size, checksum) in [
            (
                "bob",
                fixture.destination.clone(),
                6,
                fixture.checksum.clone(),
            ),
            (
                "alice",
                fixture.directory.join("other.bin"),
                6,
                fixture.checksum.clone(),
            ),
            (
                "alice",
                fixture.destination.clone(),
                7,
                fixture.checksum.clone(),
            ),
            ("alice", fixture.destination.clone(), 6, "0".repeat(64)),
        ] {
            assert!(
                fixture
                    .store
                    .begin(
                        &fixture.token,
                        user,
                        destination,
                        size,
                        Some(&checksum),
                        "request"
                    )
                    .await
                    .is_err()
            );
        }
        // Failed takeover attempts do not revoke the legitimate writer.
        upload.write(b"def").await.unwrap();
        assert_eq!(fs::read(&fixture.destination).await.unwrap(), b"abcdef");
        drop(upload);
        fixture.cleanup().await;
    }

    #[tokio::test]
    async fn checksum_failure_never_publishes_corrupt_upload() {
        let fixture = Fixture::new().await;
        let (mut upload, _, _) = fixture.begin().await;
        let error = upload.write(b"abcdeg").await.unwrap_err();
        assert!(error.to_string().contains("checksum mismatch"));
        assert!(!fs::try_exists(&fixture.destination).await.unwrap());
        assert!(
            fixture
                .store
                .begin(
                    &fixture.token,
                    "alice",
                    fixture.destination.clone(),
                    6,
                    Some(&fixture.checksum),
                    "request"
                )
                .await
                .is_err()
        );
        drop(upload);
        fixture.cleanup().await;
    }

    #[tokio::test]
    async fn upload_never_overwrites_destination_created_during_transfer() {
        let fixture = Fixture::new().await;
        let (mut upload, _, _) = fixture.begin().await;
        upload.write(b"abc").await.unwrap();
        fs::write(&fixture.destination, b"existing").await.unwrap();
        assert!(upload.write(b"def").await.is_err());
        assert_eq!(fs::read(&fixture.destination).await.unwrap(), b"existing");
        drop(upload);
        fixture.cleanup().await;
    }

    #[tokio::test]
    async fn empty_upload_completes_and_can_be_acknowledged_again() {
        let fixture = Fixture::new().await;
        let hash = crate::transfer::hex_digest(&Sha256::digest(b""));
        let (upload, offset, completed) = fixture
            .store
            .begin(
                &fixture.token,
                "alice",
                fixture.destination.clone(),
                0,
                Some(&hash),
                "request",
            )
            .await
            .unwrap();
        assert!(completed);
        assert_eq!(offset, 0);
        assert_eq!(fs::metadata(&fixture.destination).await.unwrap().len(), 0);
        fixture
            .store
            .acknowledge(&fixture.token, "alice")
            .await
            .unwrap();
        fixture
            .store
            .acknowledge(&fixture.token, "alice")
            .await
            .unwrap();
        drop(upload);
        fixture.cleanup().await;
    }
}
