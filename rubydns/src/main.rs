#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rubydns::run().await
}
