use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "jftp-server",
    about = "Serve a directory over the authenticated jftp SSH subsystem"
)]
struct Args {
    /// TCP port to listen on.
    #[arg(long, default_value_t = 2222)]
    port: u16,

    /// Filesystem root exposed to authenticated users. Defaults to the current directory.
    #[arg(long, default_value = ".")]
    path: PathBuf,

    /// TOML user repository. Defaults to the per-user jftp config directory.
    #[arg(long)]
    users: Option<PathBuf>,

    /// Persistent Ed25519 SSH host key. Created on first start if it does not exist.
    #[arg(long)]
    host_key: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    jftp::server::run(args.path, args.port, args.users, args.host_key).await
}
