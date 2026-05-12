use clap::Parser;
use ipnet::IpNet;
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
// const CMD_UDP_ASSOCIATE: u8 = 0x03;

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
}

#[derive(Clone)]
struct ServerConfig {
    username: String,
    password: String,
    send_through: Option<IpNet>,
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
    /// Username for authentication
    #[arg(short, long)]
    username: String,

    /// Password for authentication
    #[arg(short, long)]
    password: String,

    /// Port to listen on
    #[arg(long, default_value = "1080")]
    port: u16,

    /// Address to bind to
    #[arg(long, default_value = "0.0.0.0")]
    bind: String,

    /// CIDR range for outbound source IP (e.g., 2a06:a005:1c40::/44)
    #[arg(long)]
    send_through: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let args = Args::parse();

    let send_through = args.send_through.map(|s| {
        s.parse::<IpNet>().expect("Invalid CIDR format for --send-through")
    });

    if let Some(ref cidr) = send_through {
        info!("Send through CIDR: {}", cidr);
    }

    let config = Arc::new(ServerConfig {
        username: args.username,
        password: args.password,
        send_through,
    });

    let addr = format!("{}:{}", args.bind, args.port);
    let listener = TcpListener::bind(&addr).await?;
    info!("SOCKS5 server listening on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, peer_addr, config).await {
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

async fn handle_client(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    config: Arc<ServerConfig>,
) -> Result<(), Socks5Error> {
    info!("New connection from {}", peer_addr);

    // Bound the whole handshake (greeting + auth + CONNECT). A misbehaving client that opens a
    // socket but never sends bytes would otherwise pin two fds and a task indefinitely.
    let target_stream = match timeout(HANDSHAKE_TIMEOUT, async {
        let auth_method = negotiate_auth(&mut stream).await?;
        let outbound_ip = if auth_method == AUTH_USERNAME_PASSWORD {
            let ip = authenticate(&mut stream, &config).await?;
            info!("Client {} authenticated successfully", peer_addr);
            ip
        } else {
            stream.write_all(&[SOCKS_VERSION, AUTH_NO_ACCEPTABLE]).await?;
            return Err(Socks5Error::NoAcceptableAuth);
        };
        handle_request(&mut stream, &config, outbound_ip).await
    })
    .await
    {
        Ok(result) => result?,
        Err(_) => return Err(Socks5Error::HandshakeTimeout),
    };

    // Data relay is intentionally not timed — long-lived sessions (SSH, websockets) are valid.
    relay_data(stream, target_stream).await?;

    Ok(())
}

async fn negotiate_auth(stream: &mut TcpStream) -> Result<u8, Socks5Error> {
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

    Ok(selected_method)
}

async fn authenticate(
    stream: &mut TcpStream,
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
    if username == config.username && base_password == config.password {
        stream.write_all(&[AUTH_PASSWORD_VERSION, 0x00]).await?;
        Ok(outbound_ip)
    } else {
        stream.write_all(&[AUTH_PASSWORD_VERSION, 0x01]).await?;
        Err(Socks5Error::AuthFailed)
    }
}

async fn handle_request(
    stream: &mut TcpStream,
    config: &ServerConfig,
    outbound_ip: Option<IpAddr>,
) -> Result<TcpStream, Socks5Error> {
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

    // Only support CONNECT command
    if cmd != CMD_CONNECT {
        send_reply(stream, REPLY_COMMAND_NOT_SUPPORTED, None).await?;
        return Err(Socks5Error::UnsupportedCommand(cmd));
    }

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
            Ok(target_stream)
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

async fn send_reply(
    stream: &mut TcpStream,
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
    Ok(())
}

async fn relay_data(mut client: TcpStream, mut target: TcpStream) -> Result<(), Socks5Error> {
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
