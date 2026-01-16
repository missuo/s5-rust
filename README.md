# s5-rust

A lightweight SOCKS5 proxy server written in Rust with username/password authentication support.

## Features

- SOCKS5 protocol implementation (RFC 1928)
- Username/password authentication (RFC 1929)
- CONNECT command support for TCP proxying
- IPv4, IPv6, and domain name addressing
- Async I/O with Tokio for high performance
- Configurable bind address and port

## Installation

### From Source

```bash
git clone https://github.com/yourusername/s5-rust.git
cd s5-rust
cargo build --release
```

The binary will be available at `target/release/s5-rust`.

## Usage

```bash
s5-rust --username <USERNAME> --password <PASSWORD> [OPTIONS]
```

### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--username` | `-u` | Username for authentication | Required |
| `--password` | `-p` | Password for authentication | Required |
| `--port` | | Port to listen on | `1080` |
| `--bind` | | Address to bind to | `0.0.0.0` |
| `--help` | `-h` | Print help information | |

### Examples

Start the server with default settings:

```bash
s5-rust -u myuser -p mypassword
```

Start on a custom port:

```bash
s5-rust -u myuser -p mypassword --port 8080
```

Bind to localhost only:

```bash
s5-rust -u myuser -p mypassword --bind 127.0.0.1 --port 1080
```

## Testing

### Using curl

```bash
curl --socks5 127.0.0.1:1080 --proxy-user myuser:mypassword http://httpbin.org/ip
```

### Using curl with HTTPS

```bash
curl --socks5-hostname 127.0.0.1:1080 --proxy-user myuser:mypassword https://httpbin.org/ip
```

### Browser Configuration

Configure your browser to use SOCKS5 proxy:
- Host: `127.0.0.1` (or your server IP)
- Port: `1080` (or your configured port)
- Username: your configured username
- Password: your configured password

## Environment Variables

Enable debug logging:

```bash
RUST_LOG=debug s5-rust -u myuser -p mypassword
```

## License

MIT
