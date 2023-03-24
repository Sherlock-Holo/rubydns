use std::net::SocketAddr;
use std::path::Path;

use serde::Deserialize;
use tokio::fs;

use crate::plugins::PluginConfig;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub plugin_dir: String,
    pub servers: Vec<Server>,
}

impl Config {
    pub async fn parse(path: &Path) -> anyhow::Result<Self> {
        let data = fs::read(path).await?;

        Ok(serde_yaml::from_slice(&data)?)
    }
}

#[derive(Debug, Deserialize)]
pub struct Server {
    pub listen_addr: SocketAddr,
    pub plugins: Vec<PluginConfig>,
}
