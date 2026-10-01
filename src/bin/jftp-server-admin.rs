use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    jftp::admin::run(jftp::admin::AdminArgs::parse()).await
}
