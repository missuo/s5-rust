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

### Quick Install (Linux)

```bash
bash <(curl -Ls https://s.ee/socks5)
```

This will open an interactive menu to install and configure the server.

### From Source

```bash
git clone https://github.com/missuo/s5-rust.git
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
| `--send-through` | | CIDR range for outbound source IP | None |
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

Use a specific CIDR range for outbound connections (useful for servers with multiple IPs):

```bash
s5-rust -u myuser -p mypassword --send-through 2a06:a005:1c40::/48
```

This will randomly select an IP from the specified CIDR range for each outbound connection.

#### Pinning a specific outbound IP per connection

When `--send-through` is set, clients can pin a specific source IP for a single connection by appending `@<IP>` to the password. The IP must fall within the configured CIDR; otherwise the suffix is ignored and the whole string is treated as the password (which will fail authentication).

For example, with the server started as:

```bash
s5-rust -u myuser -p Hello2025 --send-through 2a06:a005:1c40::/44
```

| Client password | Outbound source IP |
|-----------------|--------------------|
| `Hello2025` | Random IP from `2a06:a005:1c40::/44` |
| `Hello2025@2a06:a005:1c40::1` | `2a06:a005:1c40::1` |
| `Hello2025@1.2.3.4` (not in CIDR) | Auth fails |

Note: the configured password should not end with `@<IP-within-CIDR>`, since that suffix would be parsed as a pin request.

## Testing

### Using curl

```bash
curl --socks5 127.0.0.1:1080 --proxy-user myuser:mypassword http://httpbin.org/ip
```

### Using curl with HTTPS

```bash
curl --socks5-hostname 127.0.0.1:1080 --proxy-user myuser:mypassword https://httpbin.org/ip
```

### Using curl with proxy URL

You can also use the `--proxy` option with a SOCKS5 URL:

```bash
curl --proxy socks5h://myuser:mypassword@127.0.0.1:1080 http://httpbin.org/ip
```

To verify the outbound IPv6 address (useful when using `--send-through`):

```bash
curl --proxy socks5h://myuser:mypassword@your-server-ip:1080 http://ipv6.ip.sb
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
