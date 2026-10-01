use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncWrite, AsyncWriteExt};

pub const SUBSYSTEM_NAME: &str = "jftp";
pub const MAX_JSON_LINE: usize = 1024 * 1024;
pub const TRANSFER_CHUNK_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Request {
    pub id: String,
    pub command: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub offset: u64,
    #[serde(default)]
    pub transfer_id: Option<String>,
    #[serde(default)]
    pub checksum: Option<String>,
    #[serde(default)]
    pub recursive: bool,
}

pub async fn write_jsonl<W>(writer: &mut W, value: &Value) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let line = serde_json::to_vec(value)?;
    writer.write_all(&line).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

pub fn event(event_type: &str, id: &str) -> Value {
    serde_json::json!({"type": event_type, "id": id})
}
