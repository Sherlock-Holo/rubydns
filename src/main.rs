use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[compio::main]
async fn main() -> anyhow::Result<()> {
    rubydns::run().await
}
