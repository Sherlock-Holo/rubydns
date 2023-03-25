# rubydns
a wasm plugin dns server

## plugin compile

1. `cd plugin/{plugin}`
2. `wasm-tools component new ../../target/wasm32-wasi/release/{plugin}.wasm -o ../../target/{plugin}.wasm --adapt ../../wasi_snapshot_preview1.wasm`
