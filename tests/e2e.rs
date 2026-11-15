//! End-to-end tests: each one starts the real binary on a free port and talks
//! to it over loopback with a minimal SOCKS5 client written here, against
//! local TCP/UDP echo servers.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use ring::digest::{digest, SHA256};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

/// The binary under test. Overridable so a test build cross-compiled on one
/// machine can run on another, where the build-time path does not exist.
fn server_bin() -> String {
    std::env::var("S5_RUST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_s5-rust").to_string())
}

const USER: &str = "alice";
const PASS: &str = "s3cret";
const T: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------- harness

struct Server {
    child: Child,
    port: u16,
    log: std::path::PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if !std::thread::panicking() {
            let _ = std::fs::remove_file(&self.log);
        }
    }
}

/// A pseudo-random port in `range`, for the one test that needs a fixed
/// range. Servers are never given a port: they bind port 0 and report what
/// they got, because any pick-then-release scheme races the other tests'
/// sockets.
fn rand_port(range: std::ops::Range<u16>, salt: u64) -> u16 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(salt);
    range.start + (h.finish() % u64::from(range.end - range.start)) as u16
}

static NEXT_LOG: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

async fn start(extra: &[&str]) -> Server {
    let mut args = vec![
        "-u".to_string(),
        USER.into(),
        "-p".into(),
        PASS.into(),
        "--bind".into(),
        "127.0.0.1".into(),
        "--port".into(),
        "0".into(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    let log = std::env::temp_dir().join(format!(
        "s5-rust-e2e-{}-{}.log",
        std::process::id(),
        NEXT_LOG.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let mut child = Command::new(server_bin())
        .args(&args)
        .env("RUST_LOG", "debug")
        .env("NO_COLOR", "1")
        .stdout(Stdio::from(std::fs::File::create(&log).unwrap()))
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn s5-rust");
    for _ in 0..200 {
        if let Some(status) = child.try_wait().unwrap() {
            panic!(
                "server exited during startup: {status}\n{}",
                std::fs::read_to_string(&log).unwrap_or_default()
            );
        }
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        if let Some(i) = text.find("listening on 127.0.0.1:") {
            let digits: String = text[i + "listening on 127.0.0.1:".len()..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            let port = digits.parse().expect("port in startup line");
            return Server { child, port, log };
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("server did not start");
}

impl Server {
    fn addr(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, self.port))
    }
    async fn tcp(&self) -> TcpStream {
        TcpStream::connect(self.addr()).await.unwrap()
    }
}

/// UDP echo that answers "<source addr>|<payload>", so tests can see which
/// address the relay sent from.
async fn udp_echo(bind: &str) -> SocketAddr {
    let sock = UdpSocket::bind(bind).await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        loop {
            let Ok((n, src)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let mut out = format!("{src}|").into_bytes();
            out.extend_from_slice(&buf[..n]);
            let _ = sock.send_to(&out, src).await;
        }
    });
    addr
}

async fn tcp_echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

// ---------------------------------------------------------------- client

async fn greet<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, user: &str, pass: &str) -> u8 {
    s.write_all(&[5, 1, 2]).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r, [5, 2]);
    let mut req = vec![1, user.len() as u8];
    req.extend_from_slice(user.as_bytes());
    req.push(pass.len() as u8);
    req.extend_from_slice(pass.as_bytes());
    s.write_all(&req).await.unwrap();
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r[0], 1);
    r[1]
}

fn encode_addr(addr: SocketAddr) -> Vec<u8> {
    let mut v = Vec::new();
    match addr.ip() {
        IpAddr::V4(ip) => {
            v.push(1);
            v.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            v.push(4);
            v.extend_from_slice(&ip.octets());
        }
    }
    v.extend_from_slice(&addr.port().to_be_bytes());
    v
}

/// Sends a request and returns (REP, BND.ADDR).
async fn request<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    cmd: u8,
    addr: SocketAddr,
) -> (u8, SocketAddr) {
    let mut req = vec![5, cmd, 0];
    req.extend(encode_addr(addr));
    s.write_all(&req).await.unwrap();
    read_reply(s).await
}

async fn read_reply<S: AsyncRead + Unpin>(s: &mut S) -> (u8, SocketAddr) {
    let mut h = [0u8; 4];
    s.read_exact(&mut h).await.unwrap();
    assert_eq!(h[0], 5);
    assert_eq!(h[2], 0);
    let ip: IpAddr = match h[3] {
        1 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await.unwrap();
            Ipv4Addr::from(b).into()
        }
        4 => {
            let mut b = [0u8; 16];
            s.read_exact(&mut b).await.unwrap();
            std::net::Ipv6Addr::from(b).into()
        }
        t => panic!("reply ATYP {t}"),
    };
    let mut p = [0u8; 2];
    s.read_exact(&mut p).await.unwrap();
    (h[1], SocketAddr::new(ip, u16::from_be_bytes(p)))
}

async fn associate<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> SocketAddr {
    assert_eq!(greet(s, USER, PASS).await, 0);
    let (rep, bnd) = request(s, 3, "0.0.0.0:0".parse().unwrap()).await;
    assert_eq!(rep, 0, "UDP ASSOCIATE refused");
    bnd
}

/// Where to send datagrams: the advertised address, or the server's when the
/// reply is unspecified (how Surge and most clients read it).
fn relay_addr(server: &Server, bnd: SocketAddr) -> SocketAddr {
    assert_ne!(bnd.port(), 0);
    if bnd.ip().is_unspecified() {
        SocketAddr::new(server.addr().ip(), bnd.port())
    } else {
        bnd
    }
}

fn wrap(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0, 0, 0];
    v.extend(encode_addr(target));
    v.extend_from_slice(payload);
    v
}

fn wrap_domain(name: &str, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0, 0, 0, 3, name.len() as u8];
    v.extend_from_slice(name.as_bytes());
    v.extend_from_slice(&port.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// Receives one relayed datagram and returns (source in header, payload).
async fn recv_relayed(sock: &UdpSocket) -> Option<(SocketAddr, Vec<u8>)> {
    let mut buf = vec![0u8; 70_000];
    let (n, _) = timeout(Duration::from_millis(800), sock.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    let b = &buf[..n];
    assert_eq!(&b[..3], &[0, 0, 0], "RSV/FRAG in reply");
    let (src, used): (SocketAddr, usize) = match b[3] {
        1 => (
            SocketAddr::new(
                Ipv4Addr::new(b[4], b[5], b[6], b[7]).into(),
                u16::from_be_bytes([b[8], b[9]]),
            ),
            10,
        ),
        4 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[4..20]);
            (
                SocketAddr::new(
                    std::net::Ipv6Addr::from(o).into(),
                    u16::from_be_bytes([b[20], b[21]]),
                ),
                22,
            )
        }
        t => panic!("reply datagram ATYP {t}"),
    };
    Some((src, b[used..].to_vec()))
}

/// Echo payload as "<seen source>|<data>" -> (seen source, data).
fn split_echo(p: &[u8]) -> (SocketAddr, Vec<u8>) {
    let i = p.iter().position(|&c| c == b'|').unwrap();
    (
        std::str::from_utf8(&p[..i]).unwrap().parse().unwrap(),
        p[i + 1..].to_vec(),
    )
}

/// UDP sockets the server process holds, from lsof. Checked on the process
/// itself rather than by re-binding the port, which other tests running in
/// parallel may legitimately have taken in the meantime.
#[cfg(target_os = "linux")]
fn server_udp_sockets(srv: &Server) -> usize {
    // /proc rather than lsof, which minimal Linux installs do not have: the
    // process's socket fds whose inodes appear in the UDP tables.
    let mut udp_inodes = std::collections::HashSet::new();
    for table in ["/proc/net/udp", "/proc/net/udp6"] {
        for line in std::fs::read_to_string(table)
            .unwrap_or_default()
            .lines()
            .skip(1)
        {
            if let Some(inode) = line.split_whitespace().nth(9) {
                udp_inodes.insert(inode.to_string());
            }
        }
    }
    std::fs::read_dir(format!("/proc/{}/fd", srv.child.id()))
        .map(|dir| {
            dir.filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
                .filter_map(|t| {
                    let t = t.to_string_lossy().into_owned();
                    t.strip_prefix("socket:[")?
                        .strip_suffix(']')
                        .map(str::to_string)
                })
                .filter(|inode| udp_inodes.contains(inode))
                .count()
        })
        .unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
fn server_udp_sockets(srv: &Server) -> usize {
    let out = Command::new("lsof")
        .args(["-nP", "-a", "-p", &srv.child.id().to_string(), "-iUDP"])
        .output()
        .expect("lsof");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.contains("UDP"))
        .count()
}

/// Waits up to 3 s for the server to hold exactly `want` UDP sockets.
async fn expect_udp_sockets(srv: &Server, want: usize) {
    let mut have = usize::MAX;
    for _ in 0..60 {
        have = server_udp_sockets(srv);
        if have == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("server holds {have} UDP sockets, expected {want}");
}

async fn closed_by_server<S: AsyncRead + Unpin>(s: &mut S, within: Duration) -> bool {
    let mut b = [0u8; 1];
    matches!(
        timeout(within, s.read(&mut b)).await,
        Ok(Ok(0)) | Ok(Err(_))
    )
}

// ------------------------------------------------------------- TCP basics

#[tokio::test]
async fn connect_still_works() {
    let srv = start(&[]).await;
    let echo = tcp_echo().await;
    let mut s = srv.tcp().await;
    assert_eq!(greet(&mut s, USER, PASS).await, 0);
    let (rep, _) = request(&mut s, 1, echo).await;
    assert_eq!(rep, 0);
    s.write_all(b"ping").await.unwrap();
    let mut b = [0u8; 4];
    s.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"ping");
}

#[tokio::test]
async fn wrong_password_is_refused() {
    let srv = start(&["--udp"]).await;
    let mut s = srv.tcp().await;
    assert_eq!(greet(&mut s, USER, "nope").await, 1);
    assert!(closed_by_server(&mut s, T).await);
}

#[tokio::test]
async fn no_auth_offer_gets_ff_once() {
    let srv = start(&[]).await;
    let mut s = srv.tcp().await;
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut all = Vec::new();
    let r = timeout(T, s.read_to_end(&mut all)).await.unwrap();
    if r.is_err() {
        tokio::time::sleep(Duration::from_millis(200)).await;
        panic!(
            "read error {:?} after {:?}; server log:\n{}",
            r,
            all,
            std::fs::read_to_string(&srv.log).unwrap_or_default()
        );
    }
    assert_eq!(all, vec![5, 0xff], "exactly one method-selection reply");
}

// --------------------------------------------------------------------- UDP

#[tokio::test]
async fn udp_associate_is_refused_unless_enabled() {
    let srv = start(&[]).await;
    let mut s = srv.tcp().await;
    assert_eq!(greet(&mut s, USER, PASS).await, 0);
    let (rep, _) = request(&mut s, 3, "0.0.0.0:0".parse().unwrap()).await;
    assert_eq!(rep, 7, "command not supported");
}

#[tokio::test]
async fn bind_command_is_still_refused() {
    let srv = start(&["--udp"]).await;
    let mut s = srv.tcp().await;
    assert_eq!(greet(&mut s, USER, PASS).await, 0);
    let (rep, _) = request(&mut s, 2, "0.0.0.0:0".parse().unwrap()).await;
    assert_eq!(rep, 7);
}

#[tokio::test]
async fn udp_relays_ipv4_both_ways() {
    let srv = start(&["--udp"]).await;
    let echo = udp_echo("127.0.0.1:0").await;
    let mut ctl = srv.tcp().await;
    let bnd = associate(&mut ctl).await;
    assert_eq!(
        bnd.ip(),
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        "default reply is unspecified"
    );
    let relay = relay_addr(&srv, bnd);

    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for i in 0..20u32 {
        let payload = format!("hello-{i}");
        c.send_to(&wrap(echo, payload.as_bytes()), relay)
            .await
            .unwrap();
        let (src, data) = recv_relayed(&c).await.expect("reply");
        assert_eq!(src, echo, "header names the target that answered");
        let (seen, data) = split_echo(&data);
        assert_eq!(data, payload.as_bytes());
        assert_eq!(seen.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_ne!(seen.port(), relay.port(), "outbound is a separate socket");
    }
}

#[tokio::test]
async fn udp_keeps_one_outbound_port_per_association() {
    let srv = start(&["--udp"]).await;
    let echo1 = udp_echo("127.0.0.1:0").await;
    let echo2 = udp_echo("127.0.0.1:0").await;
    let mut ctl = srv.tcp().await;
    let relay = relay_addr(&srv, associate(&mut ctl).await);
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    c.send_to(&wrap(echo1, b"a"), relay).await.unwrap();
    let (seen1, _) = split_echo(&recv_relayed(&c).await.unwrap().1);
    c.send_to(&wrap(echo2, b"b"), relay).await.unwrap();
    let (seen2, _) = split_echo(&recv_relayed(&c).await.unwrap().1);
    // Same source for different targets: endpoint-independent mapping, which
    // is what QUIC, STUN and games expect.
    assert_eq!(seen1, seen2);
}

#[tokio::test]
async fn udp_is_full_cone_for_the_association() {
    // A third party that learns the outbound address can reach the client:
    // endpoint-independent filtering, the "full cone" Surge reports as NAT
    // type A.
    let srv = start(&["--udp"]).await;
    let echo = udp_echo("127.0.0.1:0").await;
    let mut ctl = srv.tcp().await;
    let relay = relay_addr(&srv, associate(&mut ctl).await);
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    c.send_to(&wrap(echo, b"x"), relay).await.unwrap();
    let (outbound, _) = split_echo(&recv_relayed(&c).await.unwrap().1);

    let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    stranger.send_to(b"unsolicited", outbound).await.unwrap();
    let (src, data) = recv_relayed(&c).await.expect("unsolicited reply relayed");
    assert_eq!(src, stranger.local_addr().unwrap());
    assert_eq!(data, b"unsolicited");
}

#[tokio::test]
async fn udp_resolves_domain_targets() {
    let srv = start(&["--udp"]).await;
    let echo = udp_echo("127.0.0.1:0").await;
    let mut ctl = srv.tcp().await;
    let relay = relay_addr(&srv, associate(&mut ctl).await);
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // Twice, so the second goes through the cache.
    for _ in 0..2 {
        c.send_to(&wrap_domain("localhost", echo.port(), b"dns"), relay)
            .await
            .unwrap();
        let (src, data) = recv_relayed(&c).await.expect("reply via domain");
        assert_eq!(src, echo);
        assert_eq!(split_echo(&data).1, b"dns");
    }
}

#[tokio::test]
async fn udp_unresolvable_domain_does_not_kill_the_association() {
    let srv = start(&["--udp"]).await;
    let echo = udp_echo("127.0.0.1:0").await;
    let mut ctl = srv.tcp().await;
    let relay = relay_addr(&srv, associate(&mut ctl).await);
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    c.send_to(&wrap_domain("no-such-host.invalid", 9, b"x"), relay)
        .await
        .unwrap();
    assert!(recv_relayed(&c).await.is_none());
    c.send_to(&wrap(echo, b"still"), relay).await.unwrap();
    assert_eq!(split_echo(&recv_relayed(&c).await.unwrap().1).1, b"still");
}

#[tokio::test]
async fn udp_relays_ipv6_targets() {
    let Ok(probe) = UdpSocket::bind("[::1]:0").await else {
        eprintln!("no IPv6 loopback, skipping");
        return;
    };
    drop(probe);
    let srv = start(&["--udp"]).await;
    let echo = udp_echo("[::1]:0").await;
    let mut ctl = srv.tcp().await;
    let relay = relay_addr(&srv, associate(&mut ctl).await);
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    c.send_to(&wrap(echo, b"six"), relay).await.unwrap();
    let (src, data) = recv_relayed(&c).await.expect("v6 reply");
    assert_eq!(src, echo);
    assert_eq!(split_echo(&data).1, b"six");
}

#[tokio::test]
async fn udp_large_datagram() {
    // macOS caps loopback datagrams at net.inet.udp.maxdgram (9216 by
    // default); Linux carries the full 64 KiB.
    let size = if cfg!(target_os = "linux") {
        65_000
    } else {
        9_000
    };
    let srv = start(&["--udp"]).await;
    let echo = udp_echo("127.0.0.1:0").await;
    let mut ctl = srv.tcp().await;
    let relay = relay_addr(&srv, associate(&mut ctl).await);
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    // The echo adds its "<addr>|" prefix, so keep the reply under the cap too.
    let payload = &payload[..size - 64];
    c.send_to(&wrap(echo, payload), relay).await.unwrap();
    let (_, data) = recv_relayed(&c).await.expect("large reply");
    assert_eq!(split_echo(&data).1, payload);
}

#[tokio::test]
async fn udp_drops_fragments_and_garbage_but_keeps_going() {
    let srv = start(&["--udp"]).await;
    let echo = udp_echo("127.0.0.1:0").await;
    let mut ctl = srv.tcp().await;
    let relay = relay_addr(&srv, associate(&mut ctl).await);
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let mut frag = wrap(echo, b"frag");
    frag[2] = 1;
    c.send_to(&frag, relay).await.unwrap();
    c.send_to(&[0, 0], relay).await.unwrap();
    c.send_to(&[0, 0, 0, 9, 1, 2, 3, 4, 0, 1], relay)
        .await
        .unwrap();
    assert!(recv_relayed(&c).await.is_none(), "nothing relayed");

    c.send_to(&wrap(echo, b"ok"), relay).await.unwrap();
    assert_eq!(split_echo(&recv_relayed(&c).await.unwrap().1).1, b"ok");
}

#[tokio::test]
async fn udp_locks_to_the_first_client_source() {
    let srv = start(&["--udp"]).await;
    let echo = udp_echo("127.0.0.1:0").await;
    let mut ctl = srv.tcp().await;
    let relay = relay_addr(&srv, associate(&mut ctl).await);
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    first.send_to(&wrap(echo, b"1"), relay).await.unwrap();
    assert!(recv_relayed(&first).await.is_some());

    // Same host, different port: someone else on the box, or a spoofer.
    other.send_to(&wrap(echo, b"2"), relay).await.unwrap();
    assert!(recv_relayed(&other).await.is_none());
    assert!(recv_relayed(&first).await.is_none(), "not relayed at all");
}

#[tokio::test]
async fn udp_honours_the_port_named_in_the_request() {
    let srv = start(&["--udp"]).await;
    let echo = udp_echo("127.0.0.1:0").await;
    let declared = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let undeclared = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let mut ctl = srv.tcp().await;
    assert_eq!(greet(&mut ctl, USER, PASS).await, 0);
    let (rep, bnd) = request(&mut ctl, 3, declared.local_addr().unwrap()).await;
    assert_eq!(rep, 0);
    let relay = relay_addr(&srv, bnd);

    // The undeclared port is refused even though it would have been first.
    undeclared.send_to(&wrap(echo, b"no"), relay).await.unwrap();
    assert!(recv_relayed(&undeclared).await.is_none());
    declared.send_to(&wrap(echo, b"yes"), relay).await.unwrap();
    assert_eq!(
        split_echo(&recv_relayed(&declared).await.unwrap().1).1,
        b"yes"
    );
}

#[tokio::test]
async fn udp_associations_are_isolated() {
    let srv = start(&["--udp"]).await;
    let echo = udp_echo("127.0.0.1:0").await;
    let mut ctl_a = srv.tcp().await;
    let mut ctl_b = srv.tcp().await;
    let relay_a = relay_addr(&srv, associate(&mut ctl_a).await);
    let relay_b = relay_addr(&srv, associate(&mut ctl_b).await);
    assert_ne!(relay_a, relay_b, "one socket per association");

    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    a.send_to(&wrap(echo, b"from-a"), relay_a).await.unwrap();
    b.send_to(&wrap(echo, b"from-b"), relay_b).await.unwrap();
    let (seen_a, da) = split_echo(&recv_relayed(&a).await.unwrap().1);
    let (seen_b, db) = split_echo(&recv_relayed(&b).await.unwrap().1);
    assert_eq!(da, b"from-a");
    assert_eq!(db, b"from-b");
    assert_ne!(seen_a, seen_b, "separate outbound sockets");
    assert!(recv_relayed(&a).await.is_none());
    assert!(recv_relayed(&b).await.is_none());

    // B may not use A's relay port.
    b.send_to(&wrap(echo, b"hijack"), relay_a).await.unwrap();
    assert!(recv_relayed(&b).await.is_none());
    assert!(recv_relayed(&a).await.is_none());
}

#[tokio::test]
async fn udp_ends_with_the_control_connection_and_frees_the_port() {
    let srv = start(&["--udp"]).await;
    let mut ctl = srv.tcp().await;
    let echo = udp_echo("127.0.0.1:0").await;
    let relay = relay_addr(&srv, associate(&mut ctl).await);
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    c.send_to(&wrap(echo, b"x"), relay).await.unwrap();
    assert!(recv_relayed(&c).await.is_some());
    // Client socket + one outbound socket while open...
    expect_udp_sockets(&srv, 2).await;
    drop(ctl);
    // ...and none once the control connection is gone: socket and task freed.
    expect_udp_sockets(&srv, 0).await;
}

#[tokio::test]
async fn udp_data_on_control_connection_ends_association() {
    let srv = start(&["--udp"]).await;
    let mut ctl = srv.tcp().await;
    associate(&mut ctl).await;
    ctl.write_all(b"junk").await.unwrap();
    assert!(closed_by_server(&mut ctl, T).await);
}

#[tokio::test]
async fn udp_idle_association_is_closed() {
    let srv = start(&["--udp", "--udp-timeout", "1"]).await;
    let echo = udp_echo("127.0.0.1:0").await;
    let mut ctl = srv.tcp().await;
    let relay = relay_addr(&srv, associate(&mut ctl).await);
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // Traffic keeps it alive past the timeout...
    for _ in 0..4 {
        c.send_to(&wrap(echo, b"k"), relay).await.unwrap();
        assert!(recv_relayed(&c).await.is_some());
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    // ...and silence ends it, closing the control connection too.
    assert!(closed_by_server(&mut ctl, Duration::from_secs(3)).await);
}

#[tokio::test]
async fn udp_advertise_overrides_reply_address() {
    let srv = start(&["--udp", "--udp-advertise", "203.0.113.7"]).await;
    let mut ctl = srv.tcp().await;
    let bnd = associate(&mut ctl).await;
    assert_eq!(bnd.ip(), "203.0.113.7".parse::<IpAddr>().unwrap());
    assert_ne!(bnd.port(), 0);
}

#[tokio::test]
async fn udp_ports_range_is_respected_and_exhaustion_is_reported() {
    // Two adjacent free ports below every OS's ephemeral range (macOS starts
    // at 49152, Linux at 32768), where the other tests' kernel-assigned
    // sockets cannot land on them while this test runs.
    let base = (0..1000)
        .map(|i| rand_port(20_000..29_999, i))
        .find(|&p| {
            std::net::UdpSocket::bind(("127.0.0.1", p)).is_ok()
                && std::net::UdpSocket::bind(("127.0.0.1", p + 1)).is_ok()
        })
        .expect("two adjacent free ports");
    let range = format!("{}-{}", base, base + 1);
    let srv = start(&["--udp", "--udp-ports", &range]).await;
    let mut c1 = srv.tcp().await;
    let mut c2 = srv.tcp().await;
    let mut c3 = srv.tcp().await;
    let p1 = associate(&mut c1).await.port();
    let p2 = associate(&mut c2).await.port();
    assert!((base..=base + 1).contains(&p1));
    assert!((base..=base + 1).contains(&p2));
    assert_ne!(p1, p2);
    // Range full: a clean failure, not a hang or a crash.
    assert_eq!(greet(&mut c3, USER, PASS).await, 0);
    let (rep, _) = request(&mut c3, 3, "0.0.0.0:0".parse().unwrap()).await;
    assert_eq!(rep, 1, "general failure");
    // Freeing one makes room again.
    drop(c1);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut c4 = srv.tcp().await;
    assert_eq!(associate(&mut c4).await.port(), p1);
}

#[tokio::test]
async fn udp_send_through_pins_and_respects_family() {
    let srv = start(&["--udp", "--send-through", "127.0.0.1/32"]).await;
    let echo4 = udp_echo("127.0.0.1:0").await;
    let mut ctl = srv.tcp().await;
    let relay = relay_addr(&srv, associate(&mut ctl).await);
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    c.send_to(&wrap(echo4, b"p"), relay).await.unwrap();
    let (seen, _) = split_echo(&recv_relayed(&c).await.unwrap().1);
    assert_eq!(seen.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

    // A v4 source cannot reach a v6 target; dropped, association survives.
    if let Ok(s6) = UdpSocket::bind("[::1]:0").await {
        let echo6 = s6.local_addr().unwrap();
        c.send_to(&wrap(echo6, b"v6"), relay).await.unwrap();
        assert!(recv_relayed(&c).await.is_none());
    }
    c.send_to(&wrap(echo4, b"again"), relay).await.unwrap();
    assert_eq!(split_echo(&recv_relayed(&c).await.unwrap().1).1, b"again");
}

#[tokio::test]
async fn udp_password_pin_applies_to_the_association() {
    let srv = start(&["--udp", "--send-through", "127.0.0.1/32"]).await;
    let echo = udp_echo("127.0.0.1:0").await;
    let mut ctl = srv.tcp().await;
    assert_eq!(greet(&mut ctl, USER, &format!("{PASS}@127.0.0.1")).await, 0);
    let (rep, bnd) = request(&mut ctl, 3, "0.0.0.0:0".parse().unwrap()).await;
    assert_eq!(rep, 0);
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    c.send_to(&wrap(echo, b"pin"), relay_addr(&srv, bnd))
        .await
        .unwrap();
    assert_eq!(split_echo(&recv_relayed(&c).await.unwrap().1).1, b"pin");
}

#[tokio::test]
async fn udp_many_concurrent_associations() {
    let srv = Arc::new(start(&["--udp"]).await);
    let echo = udp_echo("127.0.0.1:0").await;
    let mut tasks = Vec::new();
    for id in 0..40u32 {
        let srv = Arc::clone(&srv);
        tasks.push(tokio::spawn(async move {
            let mut ctl = srv.tcp().await;
            let relay = relay_addr(&srv, associate(&mut ctl).await);
            let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            for seq in 0..25u32 {
                let msg = format!("{id}:{seq}");
                c.send_to(&wrap(echo, msg.as_bytes()), relay).await.unwrap();
                let (_, data) = recv_relayed(&c).await.expect("reply under load");
                assert_eq!(split_echo(&data).1, msg.as_bytes());
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    // All associations closed with their tasks; nothing left behind.
    expect_udp_sockets(&srv, 0).await;
}

// --------------------------------------------------------------------- TLS

#[derive(Debug)]
struct Pinned(String);

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if hex::encode(digest(&SHA256, end_entity.as_ref())) == self.0 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("fingerprint mismatch".into()))
        }
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            m,
            c,
            d,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            m,
            c,
            d,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn tls_connector(fingerprint: &str) -> tokio_rustls::TlsConnector {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(Pinned(fingerprint.to_string())))
    .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

fn fingerprint_of(cert: &Path, key: &Path) -> String {
    let out = Command::new(server_bin())
        .args([
            "--tls-cert",
            cert.to_str().unwrap(),
            "--tls-key",
            key.to_str().unwrap(),
        ])
        .arg("--print-fingerprint")
        .output()
        .unwrap();
    assert!(out.status.success());
    let fp = String::from_utf8(out.stdout).unwrap().trim().to_string();
    assert_eq!(fp.len(), 64);
    fp
}

async fn tls_server(dir: &Path, extra: &[&str]) -> (Server, String) {
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let fp = fingerprint_of(&cert, &key);
    let mut args = vec![
        "--tls-cert",
        cert.to_str().unwrap(),
        "--tls-key",
        key.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    (start(&refs).await, fp)
}

async fn tls_connect(
    srv: &Server,
    fp: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, std::io::Error> {
    let tcp = srv.tcp().await;
    tls_connector(fp)
        .connect(ServerName::try_from("s5-rust").unwrap(), tcp)
        .await
}

#[tokio::test]
async fn print_fingerprint_is_stable_and_matches_served_cert() {
    let dir = tempfile::tempdir().unwrap();
    let (srv, fp) = tls_server(dir.path(), &[]).await;
    assert_eq!(
        fp,
        fingerprint_of(&dir.path().join("cert.pem"), &dir.path().join("key.pem"))
    );
    tls_connect(&srv, &fp).await.expect("pinned handshake");
    let wrong = "0".repeat(64);
    assert!(tls_connect(&srv, &wrong).await.is_err());
}

#[tokio::test]
async fn tls_connect_and_udp_work() {
    let dir = tempfile::tempdir().unwrap();
    let (srv, fp) = tls_server(dir.path(), &["--udp"]).await;
    let tcp_target = tcp_echo().await;
    let udp_target = udp_echo("127.0.0.1:0").await;

    let mut s = tls_connect(&srv, &fp).await.unwrap();
    assert_eq!(greet(&mut s, USER, PASS).await, 0);
    let (rep, _) = request(&mut s, 1, tcp_target).await;
    assert_eq!(rep, 0);
    s.write_all(b"over tls").await.unwrap();
    s.flush().await.unwrap();
    let mut b = [0u8; 8];
    s.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"over tls");

    let mut ctl = tls_connect(&srv, &fp).await.unwrap();
    let relay = relay_addr(&srv, associate(&mut ctl).await);
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    c.send_to(&wrap(udp_target, b"udp+tls"), relay)
        .await
        .unwrap();
    assert_eq!(split_echo(&recv_relayed(&c).await.unwrap().1).1, b"udp+tls");

    // Closing the TLS control connection ends the association.
    expect_udp_sockets(&srv, 2).await;
    drop(ctl);
    expect_udp_sockets(&srv, 0).await;
}

#[tokio::test]
async fn tls_wrong_password_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (srv, fp) = tls_server(dir.path(), &[]).await;
    let mut s = tls_connect(&srv, &fp).await.unwrap();
    assert_eq!(greet(&mut s, USER, "bad").await, 1);
}

#[tokio::test]
async fn tls_port_also_serves_plain_unless_tls_only() {
    let dir = tempfile::tempdir().unwrap();
    let echo = tcp_echo().await;
    {
        let (srv, _) = tls_server(dir.path(), &[]).await;
        let mut s = srv.tcp().await;
        assert_eq!(greet(&mut s, USER, PASS).await, 0);
        assert_eq!(request(&mut s, 1, echo).await.0, 0);
    }
    let (srv, fp) = tls_server(dir.path(), &["--tls-only"]).await;
    let mut s = srv.tcp().await;
    s.write_all(&[5, 1, 2]).await.unwrap();
    let mut all = Vec::new();
    let _ = timeout(T, s.read_to_end(&mut all)).await.unwrap();
    assert!(
        all.is_empty(),
        "plain client got {all:?} on a TLS-only port"
    );
    tls_connect(&srv, &fp).await.expect("TLS still accepted");
}

#[tokio::test]
async fn tls_port_drops_other_protocols() {
    let dir = tempfile::tempdir().unwrap();
    let (srv, _) = tls_server(dir.path(), &[]).await;
    let mut s = srv.tcp().await;
    s.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let mut all = Vec::new();
    let _ = timeout(T, s.read_to_end(&mut all)).await.unwrap();
    assert!(all.is_empty());
}

#[tokio::test]
async fn tls_garbage_handshake_does_not_hurt_the_server() {
    let dir = tempfile::tempdir().unwrap();
    let (srv, fp) = tls_server(dir.path(), &[]).await;
    let mut s = srv.tcp().await;
    s.write_all(&[0x16, 3, 1, 0, 5, 1, 2, 3, 4, 5])
        .await
        .unwrap();
    let mut sink = Vec::new();
    let _ = timeout(T, s.read_to_end(&mut sink)).await;
    tls_connect(&srv, &fp).await.expect("server still serving");
}

#[cfg(unix)]
#[tokio::test]
async fn sighup_reloads_the_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let (srv, old_fp) = tls_server(dir.path(), &[]).await;

    // A renewal: generate a fresh pair elsewhere, move it over the old one.
    let other = tempfile::tempdir().unwrap();
    let new_fp = fingerprint_of(
        &other.path().join("cert.pem"),
        &other.path().join("key.pem"),
    );
    assert_ne!(old_fp, new_fp);
    std::fs::copy(other.path().join("cert.pem"), dir.path().join("cert.pem")).unwrap();
    std::fs::copy(other.path().join("key.pem"), dir.path().join("key.pem")).unwrap();

    // A connection made before the reload keeps working afterwards.
    let mut before = tls_connect(&srv, &old_fp).await.unwrap();

    Command::new("kill")
        .args(["-HUP", &srv.child.id().to_string()])
        .status()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    tls_connect(&srv, &new_fp)
        .await
        .expect("new certificate served");
    assert!(tls_connect(&srv, &old_fp).await.is_err());
    assert_eq!(greet(&mut before, USER, PASS).await, 0);

    // A broken renewal keeps the current certificate.
    std::fs::write(dir.path().join("cert.pem"), "garbage").unwrap();
    Command::new("kill")
        .args(["-HUP", &srv.child.id().to_string()])
        .status()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    tls_connect(&srv, &new_fp)
        .await
        .expect("still the good certificate");
}

#[tokio::test]
async fn udp_upstream_only_traffic_keeps_association_alive() {
    // A target that never answers (a log sink, a one-way stream): the
    // client's own sending must count as activity.
    let srv = start(&["--udp", "--udp-timeout", "1"]).await;
    let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut ctl = srv.tcp().await;
    let relay = relay_addr(&srv, associate(&mut ctl).await);
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for _ in 0..6 {
        c.send_to(&wrap(sink.local_addr().unwrap(), b"tick"), relay)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    assert!(!closed_by_server(&mut ctl, Duration::from_millis(100)).await);
    let mut got = 0;
    let mut b = [0u8; 64];
    while let Ok(Ok(_)) = timeout(Duration::from_millis(50), sink.recv_from(&mut b)).await {
        got += 1;
    }
    assert_eq!(got, 6, "every datagram delivered");
}

#[tokio::test]
async fn udp_downstream_only_traffic_keeps_association_alive() {
    // A server pushing to the client (a stream after one request).
    let srv = start(&["--udp", "--udp-timeout", "1"]).await;
    let pusher = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut ctl = srv.tcp().await;
    let relay = relay_addr(&srv, associate(&mut ctl).await);
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    c.send_to(&wrap(pusher.local_addr().unwrap(), b"subscribe"), relay)
        .await
        .unwrap();
    let mut b = [0u8; 64];
    let (_, outbound) = pusher.recv_from(&mut b).await.unwrap();
    for i in 0..6 {
        pusher
            .send_to(format!("push{i}").as_bytes(), outbound)
            .await
            .unwrap();
        let (_, data) = recv_relayed(&c).await.expect("push relayed");
        assert_eq!(data, format!("push{i}").as_bytes());
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    assert!(!closed_by_server(&mut ctl, Duration::from_millis(100)).await);
}

/// A second loopback address to send from, for source-address tests. Linux
/// routes all of 127/8 to lo; macOS only has 127.0.0.1 unless aliased.
async fn second_loopback() -> Option<UdpSocket> {
    UdpSocket::bind("127.0.0.2:0").await.ok()
}

fn server_log(srv: &Server) -> String {
    std::fs::read_to_string(&srv.log).unwrap_or_default()
}

#[tokio::test]
async fn udp_from_another_address_is_dropped_and_explained() {
    let Some(elsewhere) = second_loopback().await else {
        eprintln!("no 127.0.0.2, skipping");
        return;
    };
    let srv = start(&["--udp"]).await;
    let echo = udp_echo("127.0.0.1:0").await;
    let mut ctl = srv.tcp().await; // control from 127.0.0.1
    let relay = relay_addr(&srv, associate(&mut ctl).await);
    elsewhere.send_to(&wrap(echo, b"x"), relay).await.unwrap();
    assert!(recv_relayed(&elsewhere).await.is_none());
    tokio::time::sleep(Duration::from_millis(100)).await;
    let log = server_log(&srv);
    assert_eq!(
        log.matches("--udp-any-source").count(),
        1,
        "one warning:\n{log}"
    );
    elsewhere.send_to(&wrap(echo, b"y"), relay).await.unwrap();
    assert!(recv_relayed(&elsewhere).await.is_none());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        server_log(&srv).matches("--udp-any-source").count(),
        1,
        "not repeated"
    );
}

#[tokio::test]
async fn udp_any_source_accepts_then_locks() {
    let Some(elsewhere) = second_loopback().await else {
        eprintln!("no 127.0.0.2, skipping");
        return;
    };
    let srv = start(&["--udp", "--udp-any-source"]).await;
    let echo = udp_echo("127.0.0.1:0").await;
    let mut ctl = srv.tcp().await;
    let relay = relay_addr(&srv, associate(&mut ctl).await);
    // TCP came from 127.0.0.1, UDP from 127.0.0.2: a relay with a separate
    // UDP egress. Accepted...
    elsewhere
        .send_to(&wrap(echo, b"via relay"), relay)
        .await
        .unwrap();
    assert_eq!(
        split_echo(&recv_relayed(&elsewhere).await.unwrap().1).1,
        b"via relay"
    );
    // ...and the association is now that source's alone.
    let same_host = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    same_host
        .send_to(&wrap(echo, b"late"), relay)
        .await
        .unwrap();
    assert!(recv_relayed(&same_host).await.is_none());
    assert!(recv_relayed(&elsewhere).await.is_none());
}

#[tokio::test]
async fn rust_log_debug_is_honoured() {
    // The harness sets RUST_LOG=debug; a dropped datagram is logged at debug.
    let srv = start(&["--udp"]).await;
    let mut ctl = srv.tcp().await;
    let relay = relay_addr(&srv, associate(&mut ctl).await);
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    c.send_to(&[0, 0, 1, 1, 1, 2, 3, 4, 0, 1], relay)
        .await
        .unwrap(); // FRAG=1
    tokio::time::sleep(Duration::from_millis(200)).await;
    let log = server_log(&srv);
    assert!(
        log.contains("DEBUG"),
        "no debug output with RUST_LOG=debug:\n{log}"
    );
}
