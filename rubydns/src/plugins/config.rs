use std::collections::HashMap;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Plugin {
    pub name: String,
    pub plugin_path: Option<String>,
    #[serde(flatten)]
    pub config: HashMap<String, serde_yaml::Value>,
}
