use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

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

    /// Local IP address to listen on. Defaults to all IPv4 interfaces.
    #[arg(long, default_value_t = IpAddr::V4(Ipv4Addr::UNSPECIFIED))]
    bind: IpAddr,

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
    jftp::server::run(args.path, args.bind, args.port, args.users, args.host_key).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_defaults_to_all_ipv4_interfaces() {
        let args = Args::try_parse_from(["jftp-server"]).unwrap();
        assert_eq!(args.bind, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn bind_accepts_a_specific_ip_address() {
        let args = Args::try_parse_from(["jftp-server", "--bind", "127.0.0.1"]).unwrap();
        assert_eq!(args.bind, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }
}
