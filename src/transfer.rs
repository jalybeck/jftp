use anyhow::{Context, bail};
use sha2::{Digest, Sha256};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt},
};

use crate::protocol::TRANSFER_CHUNK_SIZE;

/// Hash the open file and rewind it, so the caller transfers the same file.
pub(crate) async fn checksum(file: &mut File) -> anyhow::Result<String> {
    file.rewind().await?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; TRANSFER_CHUNK_SIZE];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    file.rewind().await?;
    Ok(hex_digest(&hash.finalize()))
}

pub(crate) fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

pub(crate) fn validate_checksum(value: Option<&str>) -> anyhow::Result<&str> {
    let value = value.context("resumable transfer requires a SHA-256 checksum")?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("invalid SHA-256 checksum");
    }
    Ok(value)
}
