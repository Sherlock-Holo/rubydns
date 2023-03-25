#![feature(type_alias_impl_trait)]

extern crate core;

use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use clap::Parser;
use futures_util::{stream, StreamExt, TryStreamExt};
use tracing::level_filters::LevelFilter;
use tracing::subscriber;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, Registry};

use crate::config::Config;
use crate::handle::udp::UdpHandle;
use crate::plugins::{PluginChain, PluginConfig};
use crate::server::Server;

mod config;
mod handle;
mod plugins;
mod server;

#[derive(Debug, Parser)]
struct Args {
    #[clap(short, long)]
    config: PathBuf,
}

pub async fn run() -> anyhow::Result<()> {
    let args = Args::parse();

    init_log();

    let config = Config::parse(&args.config).await?;
    let plugin_dir = Path::new(&config.plugin_dir);

    let servers = stream::iter(config.servers.into_iter())
        .map(Ok::<_, anyhow::Error>)
        .and_then(|server| create_server(Path::new(plugin_dir), server.listen_addr, server.plugins))
        .try_collect::<Vec<_>>()
        .await?;

    let tasks = servers
        .into_iter()
        .map(|mut server| tokio::spawn(async move { server.serve().await }))
        .collect::<Vec<_>>();
    for task in tasks {
        task.await.unwrap();
    }

    Ok(())
}

async fn create_server(
    plugin_dir: &Path,
    listen_addr: SocketAddr,
    plugins: Vec<PluginConfig>,
) -> anyhow::Result<Server<UdpHandle>> {
    let plugin_chain = PluginChain::new(plugin_dir, plugins).await?;
    let udp_handle = UdpHandle::new(listen_addr).await?;

    Ok(Server::new(udp_handle, plugin_chain))
}

fn init_log() {
    let layer = fmt::layer()
        .pretty()
        .with_target(true)
        .with_writer(io::stderr);

    let layered = Registry::default().with(layer).with(LevelFilter::INFO);

    subscriber::set_global_default(layered).unwrap();
}
