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
| `--username` | `-u` | Username for authentication | Required unless `--token-pubkey` is set |
| `--password` | `-p` | Password for authentication | Required unless `--token-pubkey` is set |
| `--port` | | Port to listen on | `1080` |
| `--bind` | | Address to bind to | `0.0.0.0` |
| `--send-through` | | CIDR range for outbound source IP | None |
| `--token-pubkey` | | Ed25519 verifying key for signed credentials, as `<kid>:<key>`. Repeatable. | None |
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

### Signed credentials

The `@<IP>` suffix below is a **selection**, not an **enforcement**: whoever holds the password may pin any address in `--send-through`, including one you meant for somebody else. That is fine for your own client on a machine you control, and it is not something you can hand to a third party.

A signed credential is the grant itself. An issuer names one address and one expiry, signs them, and this server does nothing but check the signature — so the holder gets exactly the address they were given, until it expires, and editing either field invalidates the credential rather than changing what it permits.

Signing is asymmetric on purpose. This server holds only a **verifying** key: it can check credentials and cannot issue them, so a break-in here yields no ability to pin addresses. The signing key never leaves the issuer.

```bash
# Accepts signed credentials only — no static password on this port at all.
s5-rust --port 2334 --send-through 2a06:a005:1c40::/44 \
        --token-pubkey k1:ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c

# Or both, so one port serves your own client and issued credentials alike.
s5-rust -u myuser -p mypassword --send-through 2a06:a005:1c40::/44 \
        --token-pubkey k1:<hex-or-base64url-public-key>
```

`--token-pubkey` is repeatable, which is how a key is rotated: start issuing under a new id while this server still accepts the old, then withdraw the old. Withdrawing an id invalidates every credential issued under it at once — the only revocation there is, and the one an incident wants.

#### Credential format

```text
username: hk1.<kid>.<subject>.<expiry-unix>.<address-hex>
password: <base64url(ed25519 signature over the username)>
```

The claim travels in the username so a log line says which subject, which address, and until when. Neither field contains `:` or `@`, so a credential drops straight into a proxy URL:

```bash
curl --proxy "socks5h://hk1.k1.sbx_abc.1756400000.2602f7ee00fa00000000000000000001:<sig>@proxy:2334" https://example.com
```

The address is 8 hex digits for IPv4 and 32 for IPv6 — written normally, an IPv6 address would put colons in the userinfo and make that URL ambiguous.

A credential is refused if the signature does not verify, the key id is unknown, the expiry has passed (with 60 seconds of clock-skew grace), or the address falls outside `--send-through`. The client is told only that authentication failed; which check failed is logged here and not disclosed.

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
