# rubydns

A Rust DNS server, support multi backend

## Features

### Bind

- [x] bind UDP
- [ ] bind TCP
- [X] bind DoH
- [X] bind DoT
- [X] bind QUIC
- [X] bind DoH3

### Backend

- [x] UDP backend
- [X] DoH backend
- [X] DoT backend
- [X] QUIC backend
- [X] DoH3 backend

### Others

- [x] Cache
- [X] Route based backend choice
  - [x] dnsmasq rule support
  - [x] normal domain list support
