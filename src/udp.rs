//! SOCKS5 UDP ASSOCIATE (RFC 1928, section 7).
//!
//! Each association gets its own client-facing UDP socket, created when the
//! client sends UDP ASSOCIATE on an authenticated TCP connection and torn down
//! when that connection closes. A socket per association rather than one shared
//! port is deliberate: a shared port has to work out which association a
//! datagram belongs to from its source address alone, and two associations
//! from the same host (Surge opens one per UDP flow) cannot be told apart that
//! way. Getting it wrong would hand one flow's packets the other's outbound
//! address and lifetime. `--udp-ports` exists for the firewall cost this has.
//!
//! The datagrams themselves are never encrypted, even when the control
//! connection runs over TLS: that is how the protocol is defined.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::time::Duration;

use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Instant};
use tracing::{debug, info, warn};

use crate::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6};

/// Largest datagram we relay. A UDP payload cannot exceed this on IPv4, and
/// anything bigger on IPv6 would need jumbograms, which nothing here uses.
const MAX_DATAGRAM: usize = 65_535;
/// Room for the SOCKS5 UDP header in front of a maximum-size payload:
/// RSV(2) + FRAG(1) + ATYP(1) + domain length(1) + domain(255) + port(2).
const MAX_HEADER: usize = 262;
/// Domain lookups for UDP happen inline in the relay loop, so a slow resolver
/// stalls the association; bound it well under any sane idle timeout.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// Resolved domains kept per association. QUIC and DNS flows talk to one or
/// two names; the cap only stops a client from growing the map without bound.
const DNS_CACHE_MAX: usize = 256;
/// Attempts at finding a free port inside `--udp-ports` before giving up.
const PORT_ATTEMPTS: usize = 64;

#[derive(Clone, Debug)]
pub struct UdpSettings {
    /// Address put in the UDP ASSOCIATE reply. None picks one, see
    /// `reply_address`.
    pub advertise: Option<IpAddr>,
    /// Ports the per-association sockets may use. None lets the kernel pick.
    pub ports: Option<RangeInclusive<u16>>,
    /// An association with no traffic in either direction for this long is
    /// closed, together with its control connection.
    pub idle_timeout: Duration,
    /// Accept the client's first datagram from any address, not only from the
    /// control connection's. See `Association::client_ip`.
    pub any_source: bool,
}

/// Where a client wants a datagram to go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Ip(SocketAddr),
    Domain(String, u16),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    /// Non-zero FRAG. Reassembly is optional in the RFC and no client we care
    /// about fragments, so these are dropped as the RFC allows.
    Fragmented(u8),
    BadAddressType(u8),
    EmptyDomain,
}

/// Splits a client datagram into its destination and payload.
///
/// ```text
/// +----+------+------+----------+----------+----------+
/// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +----+------+------+----------+----------+----------+
/// | 2  |  1   |  1   | Variable |    2     | Variable |
/// +----+------+------+----------+----------+----------+
/// ```
pub fn parse_datagram(buf: &[u8]) -> Result<(Target, &[u8]), ParseError> {
    if buf.len() < 4 {
        return Err(ParseError::TooShort);
    }
    // RSV is ignored rather than required to be zero: being strict about a
    // reserved field buys nothing and breaks clients that leave junk in it.
    if buf[2] != 0 {
        return Err(ParseError::Fragmented(buf[2]));
    }
    let rest = &buf[4..];
    let (target, used) = match buf[3] {
        ATYP_IPV4 => {
            if rest.len() < 6 {
                return Err(ParseError::TooShort);
            }
            let ip = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
            let port = u16::from_be_bytes([rest[4], rest[5]]);
            (Target::Ip(SocketAddr::new(ip.into(), port)), 6)
        }
        ATYP_IPV6 => {
            if rest.len() < 18 {
                return Err(ParseError::TooShort);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&rest[..16]);
            let port = u16::from_be_bytes([rest[16], rest[17]]);
            (
                Target::Ip(SocketAddr::new(Ipv6Addr::from(octets).into(), port)),
                18,
            )
        }
        ATYP_DOMAIN => {
            let len = *rest.first().ok_or(ParseError::TooShort)? as usize;
            if len == 0 {
                return Err(ParseError::EmptyDomain);
            }
            if rest.len() < 1 + len + 2 {
                return Err(ParseError::TooShort);
            }
            let name = String::from_utf8_lossy(&rest[1..1 + len]).into_owned();
            let port = u16::from_be_bytes([rest[1 + len], rest[2 + len]]);
            (Target::Domain(name, port), 1 + len + 2)
        }
        other => return Err(ParseError::BadAddressType(other)),
    };
    Ok((target, &rest[used..]))
}

/// Writes the header for a datagram coming back from `from` into `out`,
/// returning its length. IPv4-mapped IPv6 sources are reported as IPv4, since
/// that is the address the client asked for when it sent the original packet.
pub fn write_header(from: SocketAddr, out: &mut [u8]) -> usize {
    out[0] = 0;
    out[1] = 0;
    out[2] = 0;
    let ip = from.ip().to_canonical();
    let n = match ip {
        IpAddr::V4(v4) => {
            out[3] = ATYP_IPV4;
            out[4..8].copy_from_slice(&v4.octets());
            8
        }
        IpAddr::V6(v6) => {
            out[3] = ATYP_IPV6;
            out[4..20].copy_from_slice(&v6.octets());
            20
        }
    };
    out[n..n + 2].copy_from_slice(&from.port().to_be_bytes());
    n + 2
}

/// The address the UDP ASSOCIATE reply should carry for a socket bound to
/// `bound` (which is on the address the client reached us at).
///
/// Without `--udp-advertise`: a public bound address is sent as is, and a
/// private one (this host is behind NAT) as the unspecified address.
///
/// Both halves were settled against Surge. Sent the unspecified address, it
/// uses the server's address -- but only for a direct connection; through an
/// `underlying-proxy` the 0.0.0.0 goes to the relay verbatim, which then sends
/// to itself, and nothing arrives. So a real address is sent whenever we know
/// one, and behind NAT, where we do not, the unspecified address at least
/// keeps direct clients working until `--udp-advertise` names the public one.
pub fn reply_address(bound: SocketAddr, settings: &UdpSettings) -> SocketAddr {
    let ip = match settings.advertise {
        Some(ip) => ip,
        None if is_public(bound.ip()) => bound.ip(),
        None if bound.is_ipv4() => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        None => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    SocketAddr::new(ip, bound.port())
}

/// Whether a client elsewhere on the internet could send to `ip` -- that is,
/// whether it is worth advertising. Conservative: anything special-purpose
/// counts as not public, since advertising it would strand the client.
fn is_public(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || (a == 100 && (64..128).contains(&b)) // CGNAT, 100.64.0.0/10
                || a == 0
                || a >= 240)
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (first & 0xfe00) == 0xfc00 // unique local, fc00::/7
                || (first & 0xffc0) == 0xfe80 // link local, fe80::/10
                || (first == 0x2001 && v6.segments()[1] == 0x0db8)) // documentation
        }
    }
}

/// A UDP association that has been set up and answered, waiting to be run.
pub struct Association {
    client_socket: UdpSocket,
    /// The client's address as seen on the control connection. By default
    /// datagrams from anywhere else are dropped: otherwise the port number is
    /// all that stands between this relay and anyone on the internet who
    /// sprays the port range before the client's first datagram.
    ///
    /// That breaks whenever TCP and UDP leave the client from different
    /// addresses -- a client chained through another proxy (seen with Surge
    /// and a Snell relay whose UDP egress differs from its TCP one), dual-WAN
    /// homes, TCP over IPv6 with UDP over IPv4. `--udp-any-source` trades the
    /// check for that case; the association still locks to whichever source
    /// sends the first valid datagram.
    client_ip: IpAddr,
    /// The source port the client said it would send from, when it said one.
    client_port: Option<u16>,
    /// The outbound source address for the whole association. Fixed once so a
    /// flow keeps one source address -- QUIC treats a change as migration and
    /// many servers reject it.
    outbound_ip: Option<IpAddr>,
    settings: UdpSettings,
    peer: SocketAddr,
}

impl Association {
    /// Binds the client-facing socket on `local_ip`, the address the client
    /// reached the control connection on, so replies leave from the same
    /// address the client is sending to.
    pub async fn bind(
        local_ip: IpAddr,
        peer: SocketAddr,
        requested: Option<SocketAddr>,
        outbound_ip: Option<IpAddr>,
        settings: &UdpSettings,
    ) -> io::Result<Self> {
        let client_socket = bind_in_range(local_ip, settings.ports.as_ref()).await?;
        // RFC 1928: DST.ADDR/DST.PORT in the request are where the client
        // expects to send from, and may be zero when it does not know. Behind
        // NAT the address it knows is not the one we will see, so only the
        // port is held to, and only when given.
        let client_port = requested.map(|a| a.port()).filter(|&p| p != 0);
        Ok(Self {
            client_socket,
            client_ip: peer.ip().to_canonical(),
            client_port,
            outbound_ip,
            settings: settings.clone(),
            peer,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.client_socket.local_addr()
    }

    /// Relays datagrams until the control connection closes or the
    /// association goes idle.
    pub async fn run<S: AsyncRead + Unpin>(self, control: &mut S) -> io::Result<()> {
        let Association {
            client_socket,
            client_ip,
            client_port,
            outbound_ip,
            settings,
            peer,
        } = self;

        // Sockets toward targets, made on first use per address family.
        let mut out4: Option<UdpSocket> = None;
        let mut out6: Option<UdpSocket> = None;
        // The client's UDP source, learned from its first valid datagram and
        // then held: replies go here and nowhere else.
        let mut client_src: Option<SocketAddr> = None;
        let mut warned_source = false;
        let mut dns: HashMap<String, SocketAddr> = HashMap::new();

        // One buffer for all three sockets. The loop waits for readiness and
        // only then reads, one datagram at a time, so nothing is ever read
        // into it concurrently -- which keeps an association at ~64 KiB
        // instead of one maximum-size buffer per socket. That matters because
        // clients open an association per UDP flow, thousands on a busy box.
        // Client datagrams are read to the front; target replies are read
        // after MAX_HEADER, leaving room to prepend the SOCKS5 header in place.
        let mut buf = vec![0u8; MAX_HEADER + MAX_DATAGRAM];
        let mut control_byte = [0u8; 1];

        let mut deadline = Instant::now() + settings.idle_timeout;
        let (mut up_packets, mut down_packets) = (0u64, 0u64);

        enum Wake {
            ControlClosed,
            Idle,
            Client,
            Target4,
            Target6,
        }

        loop {
            let wake = tokio::select! {
                // Anything at all on the control connection ends the
                // association: EOF and errors because the client is gone, and
                // data because nothing may follow UDP ASSOCIATE on it.
                _ = control.read(&mut control_byte) => Wake::ControlClosed,
                _ = tokio::time::sleep_until(deadline) => Wake::Idle,
                r = client_socket.readable() => { r?; Wake::Client }
                r = readable_opt(out4.as_ref()) => { r?; Wake::Target4 }
                r = readable_opt(out6.as_ref()) => { r?; Wake::Target6 }
            };

            match wake {
                Wake::ControlClosed => break,
                Wake::Idle => {
                    info!("UDP association for {} idle, closing", peer);
                    break;
                }
                Wake::Client => {
                    let Some((n, src)) = try_recv(&client_socket, &mut buf)? else {
                        continue;
                    };
                    let ip_ok = settings.any_source || src.ip().to_canonical() == client_ip;
                    if !ip_ok && client_src.is_none() && !warned_source {
                        // Once per association, at a level operators see: the
                        // symptom is otherwise just "UDP does not work".
                        warned_source = true;
                        warn!(
                            "UDP for association of {} arrived from {}, not the control \
                             connection's address; dropped (--udp-any-source accepts it)",
                            peer, src
                        );
                    }
                    if !ip_ok
                        || client_port.is_some_and(|p| p != src.port())
                        || client_src.is_some_and(|known| known != src)
                    {
                        debug!(
                            "UDP from unexpected source {} for association of {}",
                            src, peer
                        );
                        continue;
                    }
                    let (target, payload) = match parse_datagram(&buf[..n]) {
                        Ok(v) => v,
                        Err(e) => {
                            debug!("Dropping UDP datagram from {}: {:?}", src, e);
                            continue;
                        }
                    };
                    client_src.get_or_insert(src);
                    deadline = Instant::now() + settings.idle_timeout;

                    let Some(dest) = resolve(&target, outbound_ip, &mut dns).await else {
                        continue;
                    };
                    let slot = match (dest.is_ipv4(), outbound_ip) {
                        // A pinned source decides the family, as it does for
                        // TCP: a v6 source cannot reach a v4 target.
                        (true, Some(IpAddr::V6(_))) | (false, Some(IpAddr::V4(_))) => {
                            debug!("UDP target {} does not match outbound family", dest);
                            continue;
                        }
                        (true, _) => &mut out4,
                        (false, _) => &mut out6,
                    };
                    // Failing to open a socket (no IPv6 on this host, say)
                    // costs this datagram, not the association.
                    let socket = match outbound(slot, dest, outbound_ip).await {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("UDP outbound socket for {} failed: {}", dest, e);
                            continue;
                        }
                    };
                    match socket.send_to(payload, dest).await {
                        Ok(_) => up_packets += 1,
                        // A send to one bad target must not end the whole
                        // association; the next datagram may go elsewhere.
                        Err(e) => debug!("UDP send to {} failed: {}", dest, e),
                    }
                }
                Wake::Target4 | Wake::Target6 => {
                    let socket = match wake {
                        Wake::Target4 => out4.as_ref(),
                        _ => out6.as_ref(),
                    }
                    .expect("readable only once created");
                    let Some((n, from)) = try_recv(socket, &mut buf[MAX_HEADER..])? else {
                        continue;
                    };
                    // Nothing can reach a target before the client's first
                    // datagram fixes client_src, so this only skips strays.
                    let Some(dst) = client_src else { continue };
                    deadline = Instant::now() + settings.idle_timeout;
                    let packet = prepend_header(&mut buf, n, from);
                    match client_socket.send_to(packet, dst).await {
                        Ok(_) => down_packets += 1,
                        Err(e) => debug!("UDP send to client {} failed: {}", dst, e),
                    }
                }
            }
        }

        info!(
            "UDP association for {} closed ({} up, {} down)",
            peer, up_packets, down_packets
        );
        Ok(())
    }
}

/// Writes the header for `from` into the space reserved in front of the `n`
/// payload bytes at `buf[MAX_HEADER..]`, so a reply goes out without copying
/// the payload. Returns the finished packet.
fn prepend_header(buf: &mut [u8], n: usize, from: SocketAddr) -> &[u8] {
    let mut header = [0u8; 22];
    let hlen = write_header(from, &mut header);
    let start = MAX_HEADER - hlen;
    buf[start..MAX_HEADER].copy_from_slice(&header[..hlen]);
    &buf[start..MAX_HEADER + n]
}

async fn readable_opt(socket: Option<&UdpSocket>) -> io::Result<()> {
    match socket {
        Some(s) => s.readable().await,
        None => std::future::pending().await,
    }
}

/// Reads one datagram after a readiness wake-up. Ok(None) means "nothing to
/// do, wait again": a spurious wake-up, or an ICMP error surfaced on the
/// socket. Windows reports an earlier send's "port unreachable" as a reset
/// on the next receive; that is about one remote peer and must not end the
/// association for all of them.
fn try_recv(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<Option<(usize, SocketAddr)>> {
    match socket.try_recv_from(buf) {
        Ok(v) => Ok(Some(v)),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionRefused
            ) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

async fn outbound(
    slot: &mut Option<UdpSocket>,
    dest: SocketAddr,
    outbound_ip: Option<IpAddr>,
) -> io::Result<&UdpSocket> {
    if slot.is_none() {
        let bind_ip = outbound_ip.unwrap_or(if dest.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        });
        let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
        info!("UDP outbound socket {}", socket.local_addr()?);
        *slot = Some(socket);
    }
    Ok(slot.as_ref().expect("just set"))
}

async fn resolve(
    target: &Target,
    outbound_ip: Option<IpAddr>,
    cache: &mut HashMap<String, SocketAddr>,
) -> Option<SocketAddr> {
    let (name, port) = match target {
        Target::Ip(addr) => return Some(SocketAddr::new(addr.ip().to_canonical(), addr.port())),
        Target::Domain(name, port) => (name, *port),
    };
    if let Some(addr) = cache.get(name) {
        return Some(SocketAddr::new(addr.ip(), port));
    }
    let addrs: Vec<SocketAddr> =
        match timeout(DNS_TIMEOUT, tokio::net::lookup_host((name.as_str(), port))).await {
            Ok(Ok(it)) => it.collect(),
            Ok(Err(e)) => {
                debug!("UDP lookup of {} failed: {}", name, e);
                return None;
            }
            Err(_) => {
                warn!("UDP lookup of {} timed out", name);
                return None;
            }
        };
    // With a pinned source only its family is reachable; without one prefer
    // IPv4, which every host here can send from.
    let pick = match outbound_ip {
        Some(IpAddr::V6(_)) => addrs.iter().find(|a| a.is_ipv6()),
        Some(IpAddr::V4(_)) => addrs.iter().find(|a| a.is_ipv4()),
        None => addrs.iter().find(|a| a.is_ipv4()).or(addrs.first()),
    }
    .copied()?;
    if cache.len() >= DNS_CACHE_MAX {
        cache.clear();
    }
    cache.insert(name.clone(), pick);
    Some(pick)
}

async fn bind_in_range(ip: IpAddr, ports: Option<&RangeInclusive<u16>>) -> io::Result<UdpSocket> {
    let Some(range) = ports else {
        return UdpSocket::bind(SocketAddr::new(ip, 0)).await;
    };
    // Random probing rather than a scan from the start, so concurrent
    // associations do not all fight over the lowest free port.
    let span = (*range.end() as u32 - *range.start() as u32 + 1) as usize;
    let attempts = PORT_ATTEMPTS.max(span.min(1024));
    let mut last_err = None;
    for _ in 0..attempts {
        let port = rand::thread_rng().gen_range(range.clone());
        match UdpSocket::bind(SocketAddr::new(ip, port)).await {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::other("no free port in --udp-ports")))
}

/// Parses `--udp-ports START-END`.
pub fn parse_port_range(s: &str) -> Result<RangeInclusive<u16>, String> {
    let (a, b) = s
        .split_once('-')
        .ok_or_else(|| format!("expected START-END, got {s:?}"))?;
    let start: u16 = a.trim().parse().map_err(|_| format!("bad port {a:?}"))?;
    let end: u16 = b.trim().parse().map_err(|_| format!("bad port {b:?}"))?;
    if start == 0 || start > end {
        return Err(format!("bad range {s:?}"));
    }
    Ok(start..=end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_target() {
        let pkt = [0, 0, 0, ATYP_IPV4, 1, 2, 3, 4, 0x01, 0xbb, b'h', b'i'];
        let (t, payload) = parse_datagram(&pkt).unwrap();
        assert_eq!(t, Target::Ip("1.2.3.4:443".parse().unwrap()));
        assert_eq!(payload, b"hi");
    }

    #[test]
    fn parses_ipv6_target() {
        let mut pkt = vec![0, 0, 0, ATYP_IPV6];
        pkt.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        pkt.extend_from_slice(&53u16.to_be_bytes());
        pkt.extend_from_slice(b"q");
        let (t, payload) = parse_datagram(&pkt).unwrap();
        assert_eq!(t, Target::Ip("[2001:db8::1]:53".parse().unwrap()));
        assert_eq!(payload, b"q");
    }

    #[test]
    fn parses_domain_target() {
        let mut pkt = vec![0, 0, 0, ATYP_DOMAIN, 11];
        pkt.extend_from_slice(b"example.com");
        pkt.extend_from_slice(&443u16.to_be_bytes());
        let (t, payload) = parse_datagram(&pkt).unwrap();
        assert_eq!(t, Target::Domain("example.com".into(), 443));
        assert!(payload.is_empty());
    }

    #[test]
    fn rejects_truncated_and_odd_datagrams() {
        assert_eq!(parse_datagram(&[0, 0, 0]), Err(ParseError::TooShort));
        assert_eq!(
            parse_datagram(&[0, 0, 0, ATYP_IPV4, 1, 2, 3, 4, 0]),
            Err(ParseError::TooShort)
        );
        assert_eq!(
            parse_datagram(&[0, 0, 0, ATYP_IPV6, 0, 0]),
            Err(ParseError::TooShort)
        );
        assert_eq!(
            parse_datagram(&[0, 0, 0, ATYP_DOMAIN, 5, b'a', b'b']),
            Err(ParseError::TooShort)
        );
        assert_eq!(
            parse_datagram(&[0, 0, 0, ATYP_DOMAIN, 0, 0, 53]),
            Err(ParseError::EmptyDomain)
        );
        assert_eq!(
            parse_datagram(&[0, 0, 1, ATYP_IPV4, 1, 2, 3, 4, 0, 53]),
            Err(ParseError::Fragmented(1))
        );
        assert_eq!(
            parse_datagram(&[0, 0, 0, 0x09, 1, 2, 3, 4, 0, 53]),
            Err(ParseError::BadAddressType(0x09))
        );
    }

    #[test]
    fn header_round_trips_and_unmaps_ipv4() {
        let mut out = [0u8; 22];
        let n = write_header("[::ffff:8.8.8.8]:53".parse().unwrap(), &mut out);
        assert_eq!(&out[..n], &[0, 0, 0, ATYP_IPV4, 8, 8, 8, 8, 0, 53]);
        let (t, _) = parse_datagram(&out[..n]).unwrap();
        assert_eq!(t, Target::Ip("8.8.8.8:53".parse().unwrap()));

        let n = write_header("[2001:db8::2]:443".parse().unwrap(), &mut out);
        assert_eq!(n, 22);
        let (t, _) = parse_datagram(&out[..n]).unwrap();
        assert_eq!(t, Target::Ip("[2001:db8::2]:443".parse().unwrap()));
    }

    #[test]
    fn reply_address_sends_a_public_bound_address_as_is() {
        let s = UdpSettings {
            advertise: None,
            ports: None,
            idle_timeout: Duration::from_secs(1),
            any_source: false,
        };
        for a in ["209.240.165.194:4000", "[2602:f7ee:fa::1]:4000"] {
            let a: SocketAddr = a.parse().unwrap();
            assert_eq!(reply_address(a, &s), a);
        }
        // Behind NAT, CGNAT, loopback, link-local, ULA: not reachable as is.
        for a in [
            "10.115.0.46:4000",
            "172.16.0.1:4000",
            "192.168.1.2:4000",
            "100.64.1.1:4000",
            "127.0.0.1:4000",
            "169.254.1.1:4000",
        ] {
            let a: SocketAddr = a.parse().unwrap();
            assert_eq!(
                reply_address(a, &s).ip(),
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                "{a}"
            );
        }
        for a in ["[fd00::1]:4000", "[fe80::1]:4000", "[::1]:4000"] {
            let a: SocketAddr = a.parse().unwrap();
            assert_eq!(
                reply_address(a, &s).ip(),
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                "{a}"
            );
        }
    }

    #[test]
    fn reply_address_defaults_to_unspecified_of_same_family() {
        let s = UdpSettings {
            advertise: None,
            ports: None,
            idle_timeout: Duration::from_secs(1),
            any_source: false,
        };
        assert_eq!(
            reply_address("10.0.0.5:4000".parse().unwrap(), &s),
            "0.0.0.0:4000".parse().unwrap()
        );
        assert_eq!(
            reply_address("[2001:db8::5]:4000".parse().unwrap(), &s),
            "[::]:4000".parse().unwrap()
        );
        let s = UdpSettings {
            advertise: Some("203.0.113.9".parse().unwrap()),
            ..s
        };
        assert_eq!(
            reply_address("10.0.0.5:4000".parse().unwrap(), &s),
            "203.0.113.9:4000".parse().unwrap()
        );
    }

    #[test]
    fn port_range_parsing() {
        assert_eq!(parse_port_range("20000-20010"), Ok(20000..=20010));
        assert_eq!(parse_port_range("5-5"), Ok(5..=5));
        assert!(parse_port_range("0-10").is_err());
        assert!(parse_port_range("10-5").is_err());
        assert!(parse_port_range("10").is_err());
        assert!(parse_port_range("a-b").is_err());
    }
}
