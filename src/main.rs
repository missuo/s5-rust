mod tls;
mod token;
mod udp;

use clap::Parser;
use ipnet::IpNet;
use rand::Rng;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time::timeout;
use tracing::{error, info, warn};

// Bounded timeouts to prevent fd leaks from slow/stuck clients and targets.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
// Sleep after accept() error to avoid busy-looping when fd table is exhausted (EMFILE).
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

// SOCKS5 protocol constants
const SOCKS_VERSION: u8 = 0x05;

// Authentication methods
const AUTH_NO_AUTH: u8 = 0x00;
const AUTH_USERNAME_PASSWORD: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;

// Username/password auth version
const AUTH_PASSWORD_VERSION: u8 = 0x01;

// Commands
const CMD_CONNECT: u8 = 0x01;
// const CMD_BIND: u8 = 0x02;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

// Address types
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

// Reply codes
const REPLY_SUCCEEDED: u8 = 0x00;
const REPLY_GENERAL_FAILURE: u8 = 0x01;
const REPLY_CONNECTION_NOT_ALLOWED: u8 = 0x02;
// const REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
// const REPLY_HOST_UNREACHABLE: u8 = 0x04;
const REPLY_CONNECTION_REFUSED: u8 = 0x05;
// const REPLY_TTL_EXPIRED: u8 = 0x06;
const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

#[derive(Error, Debug)]
enum Socks5Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid SOCKS version: {0}")]
    InvalidVersion(u8),
    #[error("No acceptable authentication method")]
    NoAcceptableAuth,
    #[error("Authentication failed")]
    AuthFailed,
    #[error("Invalid auth version: {0}")]
    InvalidAuthVersion(u8),
    #[error("Unsupported command: {0}")]
    UnsupportedCommand(u8),
    #[error("Unsupported address type: {0}")]
    UnsupportedAddressType(u8),
    #[error("Connection failed")]
    ConnectionFailed,
    #[error("Handshake timeout")]
    HandshakeTimeout,
    #[error("Plain SOCKS5 refused (--tls-only)")]
    PlainRefused,
}

#[derive(Clone)]
struct ServerConfig {
    /// The static login, and None where this server accepts only signed
    /// credentials.
    ///
    /// Optional because the two kinds of client want different things. An
    /// operator's own forwarder runs on a trusted host and wants one long-lived
    /// login; an end user is handed a credential that names one address and
    /// expires. Running a second instance with no static login at all is what
    /// makes the second case safe to expose: there is then no password on that
    /// port that could pin anything other than what was signed for.
    static_login: Option<(String, String)>,
    /// Verifying keys for signed credentials, by key id. Empty disables them.
    keys: token::Keyring,
    send_through: Option<IpNet>,
    /// UDP ASSOCIATE settings; None answers it with "command not supported".
    udp: Option<udp::UdpSettings>,
}

fn random_ip_from_cidr(cidr: &IpNet) -> IpAddr {
    let mut rng = rand::thread_rng();
    match cidr {
        IpNet::V4(net) => {
            let network = u32::from(net.network());
            let host_bits = 32 - net.prefix_len();
            let host_part: u32 = if host_bits > 0 {
                rng.gen_range(0..(1u32 << host_bits))
            } else {
                0
            };
            IpAddr::V4(Ipv4Addr::from(network | host_part))
        }
        IpNet::V6(net) => {
            let network = u128::from(net.network());
            let host_bits = 128 - net.prefix_len();
            let host_part: u128 = if host_bits > 0 {
                if host_bits >= 128 {
                    rng.gen()
                } else {
                    rng.gen::<u128>() & ((1u128 << host_bits) - 1)
                }
            } else {
                0
            };
            IpAddr::V6(Ipv6Addr::from(network | host_part))
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "s5-rust")]
#[command(about = "A SOCKS5 proxy server with username/password authentication")]
struct Args {
    /// Username for authentication. Omit, with --token-pubkey set, to accept
    /// signed credentials only.
    #[arg(short, long, requires = "password")]
    username: Option<String>,

    /// Password for authentication
    #[arg(short, long, requires = "username")]
    password: Option<String>,

    /// Ed25519 verifying key for signed credentials, as <kid>:<key> where the
    /// key is 32 bytes in base64url or hex. Repeatable, so a new key can be
    /// accepted before the old one is withdrawn.
    ///
    /// This server never holds a signing key: it checks credentials and cannot
    /// issue them, so a break-in here yields no ability to pin addresses.
    #[arg(long = "token-pubkey", value_name = "KID:KEY")]
    token_pubkey: Vec<String>,

    /// Port to listen on
    #[arg(long, default_value = "1080")]
    port: u16,

    /// Address to bind to
    #[arg(long, default_value = "0.0.0.0")]
    bind: String,

    /// CIDR range for outbound source IP (e.g., 2a06:a005:1c40::/44)
    #[arg(long)]
    send_through: Option<String>,

    /// Enable UDP ASSOCIATE (SOCKS5 UDP relay).
    #[arg(long)]
    udp: bool,

    /// Address to put in UDP ASSOCIATE replies. By default a public local
    /// address is sent as is and a private one (behind NAT) as 0.0.0.0, which
    /// direct clients read as "the server's address". Behind NAT, set this to
    /// the public IP for clients that chain through another proxy (Surge's
    /// underlying-proxy), which pass 0.0.0.0 on literally.
    #[arg(long, value_name = "IP", requires = "udp")]
    udp_advertise: Option<IpAddr>,

    /// Restrict the per-association UDP ports to START-END, for firewalls.
    /// Each active association holds one port.
    #[arg(long, value_name = "START-END", requires = "udp", value_parser = udp::parse_port_range)]
    udp_ports: Option<std::ops::RangeInclusive<u16>>,

    /// Accept a UDP association's first datagram from any address instead of
    /// only from the control connection's. Needed when the client's UDP leaves
    /// from a different address than its TCP -- through a proxy chain (Surge
    /// underlying-proxy), dual WAN, or TCP over IPv6 with UDP over IPv4.
    #[arg(long, requires = "udp")]
    udp_any_source: bool,

    /// Close a UDP association after this many seconds without traffic.
    #[arg(long, value_name = "SECS", default_value = "300", requires = "udp")]
    udp_timeout: u64,

    /// PEM certificate (chain) for SOCKS5 over TLS. If neither this nor
    /// --tls-key exists yet, a self-signed pair is generated at these paths.
    #[arg(long, value_name = "PATH", requires = "tls_key")]
    tls_cert: Option<PathBuf>,

    /// PEM private key for SOCKS5 over TLS.
    #[arg(long, value_name = "PATH", requires = "tls_cert")]
    tls_key: Option<PathBuf>,

    /// Refuse plain SOCKS5 on this port; TLS clients only. Without it a port
    /// with TLS configured serves both, told apart by the first byte.
    #[arg(long, requires = "tls_cert")]
    tls_only: bool,

    /// Print the SHA-256 fingerprint of the TLS certificate (generating it if
    /// needed) and exit.
    #[arg(long, requires = "tls_cert")]
    print_fingerprint: bool,
}

/// The first byte of a TLS ClientHello record (content type "handshake").
const TLS_HANDSHAKE: u8 = 0x16;

/// How the listener treats a new connection.
struct Listener {
    tls: Option<Arc<tls::Tls>>,
    tls_only: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Answered before logging starts: the output is meant for scripts, and
    // log lines on the same stdout would corrupt it.
    if args.print_fingerprint {
        if let (Some(cert), Some(key)) = (&args.tls_cert, &args.tls_key) {
            let (_, fingerprint) = tls::Tls::load_or_generate(cert, key)
                .map_err(|e| format!("TLS setup failed: {e}"))?;
            println!("{fingerprint}");
        }
        return Ok(());
    }

    // Initialize logging. RUST_LOG when set, info otherwise -- the default is
    // not added on top of RUST_LOG, where it would override RUST_LOG=debug.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let tls = match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => {
            let (tls, fingerprint) = tls::Tls::load_or_generate(cert, key)
                .map_err(|e| format!("TLS setup failed: {e}"))?;
            info!("TLS certificate SHA-256 fingerprint: {}", fingerprint);
            Some(tls)
        }
        _ => None,
    };

    let send_through = args.send_through.map(|s| {
        s.parse::<IpNet>().expect("Invalid CIDR format for --send-through")
    });

    if let Some(ref cidr) = send_through {
        info!("Send through CIDR: {}", cidr);
    }

    let mut keys = HashMap::new();
    for spec in &args.token_pubkey {
        let (kid, vk) = token::parse_key(spec).expect("Invalid --token-pubkey");
        if keys.insert(kid.clone(), vk).is_some() {
            panic!("--token-pubkey {kid} given twice");
        }
        info!("Accepting signed credentials under key id {}", kid);
    }

    let static_login = match (args.username, args.password) {
        (Some(u), Some(p)) => Some((u, p)),
        _ => None,
    };

    // A server that can authenticate nobody would start, listen, and refuse
    // every connection -- which looks like a network fault from the outside and
    // takes far longer to diagnose than it should.
    if static_login.is_none() && keys.is_empty() {
        panic!("no way to authenticate: pass --username/--password, --token-pubkey, or both");
    }
    if static_login.is_none() {
        info!("Static login disabled; signed credentials only");
    }
    if keys.is_empty() {
        info!("No verifying keys configured; signed credentials disabled");
    }

    let udp = args.udp.then(|| udp::UdpSettings {
        advertise: args.udp_advertise,
        ports: args.udp_ports.clone(),
        idle_timeout: Duration::from_secs(args.udp_timeout.max(1)),
        any_source: args.udp_any_source,
    });
    if let Some(ref u) = udp {
        info!(
            "UDP ASSOCIATE enabled (advertise {}, ports {}, idle {}s, source {})",
            u.advertise.map_or("auto".to_string(), |ip| ip.to_string()),
            u.ports
                .as_ref()
                .map_or("any".to_string(), |r| format!("{}-{}", r.start(), r.end())),
            u.idle_timeout.as_secs(),
            if u.any_source {
                "any"
            } else {
                "control connection's"
            }
        );
    }

    let config = Arc::new(ServerConfig {
        static_login,
        keys,
        send_through,
        udp,
    });

    #[cfg(unix)]
    if let Some(ref tls) = tls {
        let tls = Arc::clone(tls);
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let Ok(mut hup) = signal(SignalKind::hangup()) else {
                warn!("Cannot listen for SIGHUP; TLS reload disabled");
                return;
            };
            while hup.recv().await.is_some() {
                match tls.reload() {
                    Ok(fp) => info!("TLS certificate reloaded, SHA-256 fingerprint: {}", fp),
                    Err(e) => error!("TLS reload failed, keeping the old certificate: {}", e),
                }
            }
        });
    }

    let listener_mode = Arc::new(Listener {
        tls,
        tls_only: args.tls_only,
    });

    let addr = format!("{}:{}", args.bind, args.port);
    let listener = TcpListener::bind(&addr).await?;
    info!(
        "SOCKS5 server listening on {}{}",
        // The bound address rather than the configured one, so --port 0
        // reports the port the kernel picked.
        listener.local_addr()?,
        match (&listener_mode.tls, listener_mode.tls_only) {
            (None, _) => "",
            (Some(_), false) => " (plain and TLS)",
            (Some(_), true) => " (TLS only)",
        }
    );

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let config = Arc::clone(&config);
                let mode = Arc::clone(&listener_mode);
                tokio::spawn(async move {
                    if let Err(e) = accept(stream, peer_addr, config, mode).await {
                        warn!("Error handling client {}: {}", peer_addr, e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                // EMFILE/ENFILE: the listener stays readable so a tight loop would peg a core
                // while spamming logs. Brief sleep lets the kernel and us recover.
                tokio::time::sleep(ACCEPT_BACKOFF).await;
            }
        }
    }
}

/// Decides between plain SOCKS5 and TLS for a fresh connection, then hands
/// the stream to the SOCKS5 handler.
async fn accept(
    stream: TcpStream,
    peer_addr: SocketAddr,
    config: Arc<ServerConfig>,
    mode: Arc<Listener>,
) -> Result<(), Socks5Error> {
    // The address the client reached us on; UDP associations bind here so
    // their replies leave from the address the client is talking to.
    let local_ip = stream.local_addr()?.ip();

    let Some(ref tls) = mode.tls else {
        return handle_client(stream, peer_addr, local_ip, config).await;
    };

    // A ClientHello always starts with 0x16 and a SOCKS5 greeting with 0x05,
    // so one peeked byte tells them apart without consuming anything. The
    // peek is covered by the handshake timeout like everything else before
    // authentication.
    let mut first = [0u8; 1];
    let n = match timeout(HANDSHAKE_TIMEOUT, stream.peek(&mut first)).await {
        Ok(r) => r?,
        Err(_) => return Err(Socks5Error::HandshakeTimeout),
    };
    if n == 0 {
        return Ok(());
    }
    match first[0] {
        TLS_HANDSHAKE => {
            let acceptor = tls.acceptor();
            let tls_stream = match timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(r) => r?,
                Err(_) => return Err(Socks5Error::HandshakeTimeout),
            };
            handle_client(tls_stream, peer_addr, local_ip, config).await
        }
        SOCKS_VERSION if !mode.tls_only => handle_client(stream, peer_addr, local_ip, config).await,
        SOCKS_VERSION => Err(Socks5Error::PlainRefused),
        other => Err(Socks5Error::InvalidVersion(other)),
    }
}

/// What an authenticated request turned into.
enum Session {
    Connect(TcpStream),
    Udp(udp::Association),
}

async fn handle_client<S>(
    mut stream: S,
    peer_addr: SocketAddr,
    local_ip: IpAddr,
    config: Arc<ServerConfig>,
) -> Result<(), Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    info!("New connection from {}", peer_addr);

    // Bound the whole handshake (greeting + auth + request). A misbehaving client that opens a
    // socket but never sends bytes would otherwise pin two fds and a task indefinitely.
    let session = match timeout(HANDSHAKE_TIMEOUT, async {
        let auth_method = negotiate_auth(&mut stream).await?;
        let outbound_ip = if auth_method == AUTH_USERNAME_PASSWORD {
            let ip = authenticate(&mut stream, &config).await?;
            info!("Client {} authenticated successfully", peer_addr);
            ip
        } else {
            // negotiate_auth already sent the 0xFF refusal.
            return Err(Socks5Error::NoAcceptableAuth);
        };
        handle_request(&mut stream, &config, outbound_ip, peer_addr, local_ip).await
    })
    .await
    {
        Ok(result) => result?,
        Err(_) => return Err(Socks5Error::HandshakeTimeout),
    };

    // Relays are intentionally not under the handshake timeout — long-lived
    // sessions (SSH, websockets, QUIC) are valid.
    match session {
        Session::Connect(target) => relay_data(stream, target).await?,
        Session::Udp(assoc) => assoc.run(&mut stream).await?,
    }

    Ok(())
}

async fn negotiate_auth<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<u8, Socks5Error> {
    // Read greeting
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;

    let version = buf[0];
    let nmethods = buf[1];

    if version != SOCKS_VERSION {
        return Err(Socks5Error::InvalidVersion(version));
    }

    // Read authentication methods
    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;

    // We only support username/password authentication
    let selected_method = if methods.contains(&AUTH_USERNAME_PASSWORD) {
        AUTH_USERNAME_PASSWORD
    } else if methods.contains(&AUTH_NO_AUTH) {
        // If no auth is offered but we require it, reject
        AUTH_NO_ACCEPTABLE
    } else {
        AUTH_NO_ACCEPTABLE
    };

    // Send method selection
    stream.write_all(&[SOCKS_VERSION, selected_method]).await?;
    stream.flush().await?;

    Ok(selected_method)
}

async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    config: &ServerConfig,
) -> Result<Option<IpAddr>, Socks5Error> {
    let result = authenticate_inner(stream, config).await;
    // TLS buffers writes; the status byte must reach the client either way.
    stream.flush().await?;
    result
}

async fn authenticate_inner<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    config: &ServerConfig,
) -> Result<Option<IpAddr>, Socks5Error> {
    // Read authentication request
    // +----+------+----------+------+----------+
    // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
    // +----+------+----------+------+----------+
    // | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
    // +----+------+----------+------+----------+

    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;

    let version = buf[0];
    let ulen = buf[1] as usize;

    if version != AUTH_PASSWORD_VERSION {
        stream.write_all(&[AUTH_PASSWORD_VERSION, 0x01]).await?;
        return Err(Socks5Error::InvalidAuthVersion(version));
    }

    // Read username
    let mut username = vec![0u8; ulen];
    stream.read_exact(&mut username).await?;
    let username = String::from_utf8_lossy(&username).to_string();

    // Read password length and password
    let mut plen_buf = [0u8; 1];
    stream.read_exact(&mut plen_buf).await?;
    let plen = plen_buf[0] as usize;

    let mut password = vec![0u8; plen];
    stream.read_exact(&mut password).await?;
    let password = String::from_utf8_lossy(&password).to_string();

    // A signed credential first, because the two are told apart by the username
    // and there is no point comparing one against the static password.
    //
    // The difference between them is what the address means. Under the static
    // login the address is a *selection* -- whoever holds the password may pin
    // anything in the pool, including another tenant's -- which is safe for an
    // operator's own forwarder and cannot be handed to anyone else. A signed
    // credential is a *grant*: the issuer named one address and one expiry, and
    // altering either invalidates it rather than changing what it permits.
    if token::looks_signed(&username) {
        return match token::verify(
            &username,
            &password,
            &config.keys,
            config.send_through.as_ref(),
            token::now_secs(),
        ) {
            Ok(grant) => {
                info!(
                    "Signed credential accepted: subject={} addr={} expires_in={}s",
                    grant.subject,
                    grant.addr,
                    grant.expires_at.saturating_sub(token::now_secs())
                );
                stream.write_all(&[AUTH_PASSWORD_VERSION, 0x00]).await?;
                Ok(Some(grant.addr))
            }
            Err(why) => {
                // Logged here and never told to the client, which gets the same
                // failure for all of them. Saying which check failed is telling
                // a prober where to spend their next attempt.
                warn!("Signed credential rejected: {:?}", why);
                stream.write_all(&[AUTH_PASSWORD_VERSION, 0x01]).await?;
                Err(Socks5Error::AuthFailed)
            }
        };
    }

    let Some((ref want_user, ref want_pass)) = config.static_login else {
        warn!("Static login attempted but this server accepts signed credentials only");
        stream.write_all(&[AUTH_PASSWORD_VERSION, 0x01]).await?;
        return Err(Socks5Error::AuthFailed);
    };

    // Split on the last '@'. If the right side parses as an IP and falls
    // within the configured send_through CIDR, the left side is the base
    // password and the IP is used as the outbound source. Otherwise the
    // whole string is treated as the password with no IP override.
    let (base_password, outbound_ip) = match password.rsplit_once('@') {
        Some((base, ip_str)) => match ip_str.parse::<IpAddr>() {
            Ok(ip) => match &config.send_through {
                Some(cidr) if cidr.contains(&ip) => (base.to_string(), Some(ip)),
                _ => (password.clone(), None),
            },
            Err(_) => (password.clone(), None),
        },
        None => (password.clone(), None),
    };

    // Verify credentials
    if &username == want_user && &base_password == want_pass {
        stream.write_all(&[AUTH_PASSWORD_VERSION, 0x00]).await?;
        Ok(outbound_ip)
    } else {
        stream.write_all(&[AUTH_PASSWORD_VERSION, 0x01]).await?;
        Err(Socks5Error::AuthFailed)
    }
}

async fn handle_request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    config: &ServerConfig,
    outbound_ip: Option<IpAddr>,
    peer_addr: SocketAddr,
    local_ip: IpAddr,
) -> Result<Session, Socks5Error> {
    // Read request header
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;

    let version = header[0];
    let cmd = header[1];
    // header[2] is reserved
    let atyp = header[3];

    if version != SOCKS_VERSION {
        return Err(Socks5Error::InvalidVersion(version));
    }

    let udp_settings = match cmd {
        CMD_CONNECT => None,
        CMD_UDP_ASSOCIATE if config.udp.is_some() => config.udp.as_ref(),
        _ => {
            send_reply(stream, REPLY_COMMAND_NOT_SUPPORTED, None).await?;
            return Err(Socks5Error::UnsupportedCommand(cmd));
        }
    };

    // Parse destination address
    let target_addr = match atyp {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let ip = Ipv4Addr::from(addr);
            format!("{}", ip)
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            String::from_utf8_lossy(&domain).to_string()
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let ip = Ipv6Addr::from(addr);
            format!("{}", ip)
        }
        _ => {
            send_reply(stream, REPLY_ADDRESS_TYPE_NOT_SUPPORTED, None).await?;
            return Err(Socks5Error::UnsupportedAddressType(atyp));
        }
    };

    // Read destination port
    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    if let Some(settings) = udp_settings {
        // For UDP ASSOCIATE the address names where the client will send
        // from, not a destination. A domain there is meaningless; treat it as
        // "unknown", which the RFC already allows for with zeros.
        let requested = target_addr
            .parse::<IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, port));
        // Choose the outbound address once for the whole association, like
        // a TCP connection does once per connection.
        let outbound =
            outbound_ip.or_else(|| config.send_through.as_ref().map(random_ip_from_cidr));
        let opened =
            udp::Association::bind(local_ip, peer_addr, requested, outbound, settings).await;
        let assoc = match opened {
            Ok(a) => a,
            Err(e) => {
                error!("Cannot open UDP association for {}: {}", peer_addr, e);
                send_reply(stream, REPLY_GENERAL_FAILURE, None).await?;
                return Err(Socks5Error::Io(e));
            }
        };
        let bound = assoc.local_addr()?;
        let reply_to = udp::reply_address(bound, settings);
        info!(
            "UDP association for {} on {} (reply {}){}",
            peer_addr,
            bound,
            reply_to,
            outbound.map_or(String::new(), |ip| format!(" via {}", ip))
        );
        send_reply(stream, REPLY_SUCCEEDED, Some(reply_to)).await?;
        return Ok(Session::Udp(assoc));
    }

    // Connect to target
    let target = format!("{}:{}", target_addr, port);
    let bind_ip = outbound_ip.or_else(|| config.send_through.as_ref().map(random_ip_from_cidr));
    let connect_future = async {
        if let Some(local_ip) = bind_ip {
            info!("Connecting to {} via {}", target, local_ip);

            // Async DNS resolution — never block a tokio worker on system DNS.
            let addrs = tokio::net::lookup_host(&target).await?;
            let mut last_err: Option<std::io::Error> = None;
            for addr in addrs {
                let socket = match local_ip {
                    IpAddr::V4(_) if addr.is_ipv4() => TcpSocket::new_v4()?,
                    IpAddr::V6(_) if addr.is_ipv6() => TcpSocket::new_v6()?,
                    _ => continue,
                };

                let bind_addr = SocketAddr::new(local_ip, 0);
                if socket.bind(bind_addr).is_ok() {
                    match socket.connect(addr).await {
                        Ok(stream) => return Ok(stream),
                        Err(e) => last_err = Some(e),
                    }
                }
            }
            Err(last_err.unwrap_or_else(|| {
                std::io::Error::other("No matching address family")
            }))
        } else {
            info!("Connecting to {}", target);
            TcpStream::connect(&target).await
        }
    };

    // Bound the connect attempt. Kernel default retries take ~127s — long enough for an
    // unreachable target to pile up fds and tasks. 10s covers normal RTT + retransmit.
    let connect_result = match timeout(CONNECT_TIMEOUT, connect_future).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout")),
    };

    match connect_result {
        Ok(target_stream) => {
            let local_addr = target_stream.local_addr().ok();
            send_reply(stream, REPLY_SUCCEEDED, local_addr).await?;
            Ok(Session::Connect(target_stream))
        }
        Err(e) => {
            let reply = match e.kind() {
                std::io::ErrorKind::ConnectionRefused => REPLY_CONNECTION_REFUSED,
                std::io::ErrorKind::PermissionDenied => REPLY_CONNECTION_NOT_ALLOWED,
                _ => REPLY_GENERAL_FAILURE,
            };
            send_reply(stream, reply, None).await?;
            Err(Socks5Error::ConnectionFailed)
        }
    }
}

async fn send_reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    reply: u8,
    bind_addr: Option<SocketAddr>,
) -> Result<(), Socks5Error> {
    let mut response = vec![SOCKS_VERSION, reply, 0x00];

    match bind_addr {
        Some(SocketAddr::V4(addr)) => {
            response.push(ATYP_IPV4);
            response.extend_from_slice(&addr.ip().octets());
            response.extend_from_slice(&addr.port().to_be_bytes());
        }
        Some(SocketAddr::V6(addr)) => {
            response.push(ATYP_IPV6);
            response.extend_from_slice(&addr.ip().octets());
            response.extend_from_slice(&addr.port().to_be_bytes());
        }
        None => {
            // Use 0.0.0.0:0 as placeholder
            response.push(ATYP_IPV4);
            response.extend_from_slice(&[0, 0, 0, 0]);
            response.extend_from_slice(&[0, 0]);
        }
    }

    stream.write_all(&response).await?;
    stream.flush().await?;
    Ok(())
}

async fn relay_data<S: AsyncRead + AsyncWrite + Unpin>(
    mut client: S,
    mut target: TcpStream,
) -> Result<(), Socks5Error> {
    // copy_bidirectional handles half-close correctly: when one side EOFs, it shuts down the
    // peer's write half and keeps the other direction draining until it also closes. The old
    // select! pattern raced the two copies and cancelled the slower one, leaking pending data
    // and (with TCP CLOSE_WAIT) leaking fds.
    match tokio::io::copy_bidirectional(&mut client, &mut target).await {
        Ok(_) => Ok(()),
        Err(e) if matches!(
            e.kind(),
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::NotConnected
        ) => Ok(()),
        Err(e) => Err(Socks5Error::Io(e)),
    }
}
