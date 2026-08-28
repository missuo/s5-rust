//! Signed credentials: a second way to authenticate, alongside the static one.
//!
//! The static username and password select an outbound address by suffixing the
//! password with `@<ip>`, which is a *selection* and not an *enforcement* —
//! whoever holds that password can pin any address in `--send-through`,
//! including one that belongs to somebody else. That is fine for an operator's
//! own forwarder on a trusted host, and it is not something that can be handed
//! to an end user.
//!
//! A signed credential is the grant itself. The issuer names one address and an
//! expiry, signs the pair, and this server does nothing but check the signature
//! — so a holder can use exactly the address they were given, until it expires,
//! and altering either field invalidates the credential rather than changing
//! what it permits.
//!
//! Ed25519 and not an HMAC, deliberately. A shared secret would mean this
//! machine could mint credentials as well as check them, and this machine is
//! the one on the public internet: it holds a verifying key, and the signing
//! key never leaves the issuer.
//!
//! # Wire format
//!
//! ```text
//! username: hk1.<kid>.<subject>.<expiry>.<addr-hex>
//! password: <base64url(signature)>
//! ```
//!
//! The claim travels in the username so that a proxy log line says which
//! subject, which address and until when, without the operator having to
//! correlate anything. The signature is over the username exactly as received,
//! so there is no canonicalisation step to disagree about.
//!
//! Neither field may contain `:` or `@`. That is not cosmetic: credentials are
//! pasted into `socks5://user:pass@host:port` URLs, and an address in its
//! normal colon form would make that string ambiguous. Hence the address is
//! carried as 32 hex characters, and the signature as base64url — whose
//! alphabet is `A-Za-z0-9-_`, and so is also safe there.

use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

/// The version prefix. Present so the two credential kinds can be told apart
/// before anything is parsed, and so a future format can coexist with this one.
pub const PREFIX: &str = "hk1";

/// How far the issuer's clock may run behind this one.
///
/// Both ends are expected to keep time, so this is small. It exists because
/// "expires in two hours" issued by a host thirty seconds fast should not
/// produce a credential that is already invalid when it arrives.
const CLOCK_SKEW_SECS: u64 = 60;

/// Why a credential was not accepted.
///
/// Kept apart from the SOCKS5 error type because the client is told none of
/// it: every one of these is answered with the same authentication failure,
/// and the distinction exists for the log on this side. Telling a caller
/// whether the signature or the expiry was wrong is telling them how to
/// probe.
#[derive(Debug, PartialEq)]
pub enum Denied {
    /// Not a signed credential at all; the caller should try the static path.
    NotSigned,
    Malformed(&'static str),
    UnknownKey,
    BadSignature,
    Expired { by_secs: u64 },
    /// Signed correctly for an address this server does not serve, which means
    /// a credential from another deployment or a misconfigured pool.
    OutsidePool,
}

/// What a valid credential grants.
#[derive(Debug, PartialEq)]
pub struct Grant {
    pub subject: String,
    pub addr: IpAddr,
    pub expires_at: u64,
}

/// The verifying keys this server accepts, by key id.
///
/// A map rather than a single key so that the issuer can rotate: it starts
/// signing with a new id while this server still accepts the old one, and the
/// old is removed once nothing holds a credential under it. It is also the only
/// revocation there is — dropping a key id invalidates every credential issued
/// under it at once, which is the blunt instrument an incident wants.
pub type Keyring = HashMap<String, VerifyingKey>;

/// Parses a `<kid>:<base64url-or-hex public key>` argument.
pub fn parse_key(spec: &str) -> Result<(String, VerifyingKey), String> {
    let (kid, key) = spec
        .split_once(':')
        .ok_or_else(|| format!("expected <kid>:<key>, got {spec:?}"))?;
    if kid.is_empty() || kid.contains('.') {
        return Err(format!("key id {kid:?} must be non-empty and contain no dot"));
    }
    let raw = decode_key(key).ok_or_else(|| format!("key {key:?} is not 32 bytes of base64url or hex"))?;
    let vk = VerifyingKey::from_bytes(&raw).map_err(|e| format!("key {kid}: {e}"))?;
    Ok((kid.to_string(), vk))
}

fn decode_key(s: &str) -> Option<[u8; 32]> {
    let bytes = if s.len() == 64 {
        hex::decode(s).ok()?
    } else {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .ok()?
    };
    bytes.try_into().ok()
}

/// Reports whether this username claims to be a signed credential.
///
/// Cheap and done before anything else, so an ordinary static login is never
/// put through signature parsing and a signed one is never compared against
/// the static password.
pub fn looks_signed(username: &str) -> bool {
    username.len() > PREFIX.len()
        && username.starts_with(PREFIX)
        && username.as_bytes()[PREFIX.len()] == b'.'
}

/// Verifies a credential and returns what it grants.
///
/// `now` is passed in rather than read here so the expiry logic can be tested
/// without waiting for time to pass.
pub fn verify(
    username: &str,
    password: &str,
    keys: &Keyring,
    pool: Option<&IpNet>,
    now: u64,
) -> Result<Grant, Denied> {
    if !looks_signed(username) {
        return Err(Denied::NotSigned);
    }

    // Exactly five fields. A subject containing a dot would otherwise shift
    // every field after it, and the signature would still verify over the whole
    // string -- so this is checked rather than trusted, and the issuer is
    // expected to keep dots out of subjects.
    let parts: Vec<&str> = username.split('.').collect();
    if parts.len() != 5 {
        return Err(Denied::Malformed("expected hk1.<kid>.<subject>.<expiry>.<addr>"));
    }
    let (kid, subject, expiry, addr_hex) = (parts[1], parts[2], parts[3], parts[4]);

    // The key is looked up before the signature is checked, because there is
    // nothing to check against otherwise. An unknown id is not a forgery
    // attempt on its own -- it is what a credential from a retired key looks
    // like.
    let vk = keys.get(kid).ok_or(Denied::UnknownKey)?;

    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(password)
        .map_err(|_| Denied::Malformed("signature is not base64url"))?;
    let sig_bytes: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| Denied::Malformed("signature is not 64 bytes"))?;
    let sig = Signature::from_bytes(&sig_bytes);

    // Over the username exactly as it arrived, so there is no canonical form
    // for the two ends to disagree about. verify_strict rejects the weak keys
    // and non-canonical encodings that plain verify accepts.
    vk.verify_strict(username.as_bytes(), &sig)
        .map_err(|_| Denied::BadSignature)?;

    // Only now is anything in the string worth believing. Parsing before the
    // signature check would be reading attacker-controlled input and acting on
    // it, which is the shape of most of the bugs in code like this.
    let expires_at: u64 = expiry
        .parse()
        .map_err(|_| Denied::Malformed("expiry is not a unix timestamp"))?;
    if now > expires_at + CLOCK_SKEW_SECS {
        return Err(Denied::Expired {
            by_secs: now - expires_at,
        });
    }

    let addr = parse_addr_hex(addr_hex).ok_or(Denied::Malformed("address is not 8 or 32 hex digits"))?;

    // Defence in depth. The signature already says the issuer chose this
    // address, but this server knows something the issuer might not: which
    // pool it is actually able to send from. A credential for an address
    // outside it would bind and fail at connect time, several layers from
    // anything that explains it.
    if let Some(net) = pool {
        if !net.contains(&addr) {
            return Err(Denied::OutsidePool);
        }
    }

    Ok(Grant {
        subject: subject.to_string(),
        addr,
        expires_at,
    })
}

/// Decodes an address written as plain hex: 8 digits for v4, 32 for v6.
///
/// Hex and not the usual colon form because these travel in a username that
/// gets pasted into a `socks5://user:pass@host` URL, where a colon would be
/// read as the separator.
fn parse_addr_hex(s: &str) -> Option<IpAddr> {
    match s.len() {
        8 => {
            let b: [u8; 4] = hex::decode(s).ok()?.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(b)))
        }
        32 => {
            let b: [u8; 16] = hex::decode(s).ok()?.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(b)))
        }
        _ => None,
    }
}

/// Seconds since the epoch, or 0 if the clock is before it.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const NOW: u64 = 1_756_400_000;
    const NOW_I: i64 = NOW as i64;

    fn issuer() -> (SigningKey, Keyring) {
        // A fixed key, so a failure is reproducible rather than occasionally
        // interesting.
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let mut keys = Keyring::new();
        keys.insert("k1".into(), sk.verifying_key());
        (sk, keys)
    }

    fn mint(sk: &SigningKey, kid: &str, subject: &str, exp: u64, addr: &str) -> (String, String) {
        let addr: IpAddr = addr.parse().unwrap();
        let hexed = match addr {
            IpAddr::V4(a) => hex::encode(a.octets()),
            IpAddr::V6(a) => hex::encode(a.octets()),
        };
        let username = format!("{PREFIX}.{kid}.{subject}.{exp}.{hexed}");
        let sig = sk.sign(username.as_bytes());
        let password =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
        (username, password)
    }

    fn pool() -> IpNet {
        "2602:f7ee:fa::/48".parse().unwrap()
    }

    #[test]
    fn a_credential_grants_exactly_the_address_it_names() {
        let (sk, keys) = issuer();
        let (u, p) = mint(&sk, "k1", "sbx_abc", NOW + 3600, "2602:f7ee:fa:0::1");

        let g = verify(&u, &p, &keys, Some(&pool()), NOW).expect("should verify");
        assert_eq!(g.addr, "2602:f7ee:fa:0::1".parse::<IpAddr>().unwrap());
        assert_eq!(g.subject, "sbx_abc");
        assert_eq!(g.expires_at, NOW + 3600);
    }

    // The whole point. A holder who edits the address to somebody else's must
    // get a refusal, not that address.
    #[test]
    fn editing_the_address_invalidates_the_credential() {
        let (sk, keys) = issuer();
        let (u, p) = mint(&sk, "k1", "sbx_abc", NOW + 3600, "2602:f7ee:fa:0::1");

        let neighbour = u.replace(
            &hex::encode("2602:f7ee:fa:0::1".parse::<Ipv6Addr>().unwrap().octets()),
            &hex::encode("2602:f7ee:fa:1::9".parse::<Ipv6Addr>().unwrap().octets()),
        );
        assert_ne!(neighbour, u, "the test did not actually change the address");
        assert_eq!(
            verify(&neighbour, &p, &keys, Some(&pool()), NOW),
            Err(Denied::BadSignature)
        );
    }

    // And the other field worth editing.
    #[test]
    fn extending_the_expiry_invalidates_the_credential() {
        let (sk, keys) = issuer();
        let (u, p) = mint(&sk, "k1", "sbx_abc", NOW + 60, "2602:f7ee:fa:0::1");
        let longer = u.replace(&(NOW + 60).to_string(), &(NOW + 999_999).to_string());
        assert_eq!(
            verify(&longer, &p, &keys, Some(&pool()), NOW),
            Err(Denied::BadSignature)
        );
    }

    #[test]
    fn an_expired_credential_is_refused() {
        let (sk, keys) = issuer();
        let (u, p) = mint(&sk, "k1", "sbx_abc", NOW - 3600, "2602:f7ee:fa:0::1");
        match verify(&u, &p, &keys, Some(&pool()), NOW) {
            Err(Denied::Expired { by_secs }) => assert_eq!(by_secs, 3600),
            other => panic!("expected expiry, got {other:?}"),
        }
    }

    // Issued a moment ago by a host whose clock is slightly ahead of this one.
    //
    // The tolerance only ever extends a credential's life, which is the safe
    // direction: an issuer running fast produces one that lasts marginally
    // longer than asked, and an issuer running slow would otherwise produce one
    // already expired on arrival. Sixty seconds against a two-hour credential
    // is noise, and the bound that actually matters -- shorter than the address
    // cooldown -- has hours of room.
    //
    // The boundary is pinned in both directions because it is genuinely easy to
    // misread: an expiry exactly CLOCK_SKEW_SECS in the past is still accepted,
    // and one second further is not.
    #[test]
    fn clock_skew_is_tolerated_up_to_the_boundary_and_no_further() {
        let (sk, keys) = issuer();

        for (label, exp, want_ok) in [
            ("not yet expired", NOW_I + 30, true),
            ("just expired, inside the tolerance", NOW_I - 30, true),
            ("exactly at the tolerance", NOW_I - CLOCK_SKEW_SECS as i64, true),
            ("one second past it", NOW_I - CLOCK_SKEW_SECS as i64 - 1, false),
            ("long gone", NOW_I - 3600, false),
        ] {
            let (u, p) = mint(&sk, "k1", "sbx_abc", exp as u64, "2602:f7ee:fa:0::1");
            let got = verify(&u, &p, &keys, Some(&pool()), NOW);
            assert_eq!(got.is_ok(), want_ok, "{label}: got {got:?}");
        }
    }

    #[test]
    fn a_credential_from_an_unknown_key_is_refused() {
        let (sk, _) = issuer();
        let (u, p) = mint(&sk, "k9", "sbx_abc", NOW + 3600, "2602:f7ee:fa:0::1");
        let (_, keys) = issuer(); // knows k1 only
        assert_eq!(verify(&u, &p, &keys, Some(&pool()), NOW), Err(Denied::UnknownKey));
    }

    // Someone else's signing key, correctly formed and correctly signed.
    #[test]
    fn a_credential_signed_by_a_stranger_is_refused() {
        let stranger = SigningKey::from_bytes(&[9u8; 32]);
        let (u, p) = mint(&stranger, "k1", "sbx_abc", NOW + 3600, "2602:f7ee:fa:0::1");
        let (_, keys) = issuer();
        assert_eq!(verify(&u, &p, &keys, Some(&pool()), NOW), Err(Denied::BadSignature));
    }

    // A valid credential from a deployment whose pool this server does not
    // serve. The signature is fine; the address is not ours to send from.
    #[test]
    fn an_address_outside_the_pool_is_refused() {
        let (sk, keys) = issuer();
        let (u, p) = mint(&sk, "k1", "sbx_abc", NOW + 3600, "2001:db8::1");
        assert_eq!(verify(&u, &p, &keys, Some(&pool()), NOW), Err(Denied::OutsidePool));
    }

    // An ordinary static login must fall through untouched rather than be
    // mangled by this path.
    #[test]
    fn a_static_username_is_not_treated_as_a_credential() {
        let (_, keys) = issuer();
        assert_eq!(
            verify("vincent", "hunter2", &keys, Some(&pool()), NOW),
            Err(Denied::NotSigned)
        );
    }

    // Credentials get pasted into socks5://user:pass@host:port. A colon or an
    // at-sign in either field makes that string ambiguous, which is why the
    // address is hex and the signature base64url.
    #[test]
    fn a_credential_is_safe_to_put_in_a_url() {
        let (sk, _) = issuer();
        let (u, p) = mint(&sk, "k1", "sbx_abc", NOW + 3600, "2602:f7ee:fa:0::1");
        for (what, field) in [("username", &u), ("password", &p)] {
            assert!(
                !field.contains(':') && !field.contains('@') && !field.contains('/'),
                "{what} {field:?} cannot go in a proxy URL"
            );
        }
    }

    #[test]
    fn a_malformed_username_is_refused_rather_than_panicking() {
        let (_, keys) = issuer();
        for bad in [
            "hk1.",
            "hk1.k1",
            "hk1.k1.sbx.notanumber.2602f7ee00fa0000000000000000000",
            "hk1.k1.sbx.1756400000.zzzz",
            "hk1.k1.sbx.1756400000.2602f7ee",
            "hk1.k1.sbx.with.too.many.dots.1756400000.00",
        ] {
            let got = verify(bad, "AAAA", &keys, Some(&pool()), NOW);
            assert!(got.is_err(), "{bad:?} was accepted");
        }
    }

    // The format lives in two codebases and two languages: hoko issues, this
    // verifies. This vector is the fixed point between them -- hoko has a test
    // asserting it produces exactly this, so a change on either side that the
    // other did not follow fails here or there, rather than in production where
    // the symptom is every user credential rejected as a bad signature.
    //
    // If this test has to change, the one in hoko's internal/egress changes
    // with it.
    #[test]
    fn the_golden_vector_from_the_issuer_verifies() {
        const USERNAME: &str = "hk1.k1.sbx_golden.1756400000.2602f7ee00fa00000000000000000001";
        const PASSWORD: &str =
            "pIW79zzCV9MqiZ3w7k0RNxTw6EAtXcbNOPoohJJu5VGB-kUuaNW1Ys_bMbqtdVWGBoYHLN4m80OtCaeyI6F-Aw";
        const PUBKEY: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";

        let (kid, vk) = parse_key(&format!("k1:{PUBKEY}")).expect("the issuer's public key");
        let mut keys = Keyring::new();
        keys.insert(kid, vk);

        // Just before it expires, since the vector has a fixed expiry.
        let grant = verify(USERNAME, PASSWORD, &keys, Some(&pool()), 1_756_400_000 - 1)
            .expect("the issuer's credential must verify here");
        assert_eq!(grant.subject, "sbx_golden");
        assert_eq!(grant.addr, "2602:f7ee:fa::1".parse::<IpAddr>().unwrap());
        assert_eq!(grant.expires_at, 1_756_400_000);
    }

    #[test]
    fn keys_parse_from_hex_and_from_base64url() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let raw = sk.verifying_key().to_bytes();
        let as_hex = format!("k1:{}", hex::encode(raw));
        let as_b64 = format!(
            "k1:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
        );
        assert_eq!(parse_key(&as_hex).unwrap().1, sk.verifying_key());
        assert_eq!(parse_key(&as_b64).unwrap().1, sk.verifying_key());
        assert!(parse_key("nokey").is_err());
        assert!(parse_key("k.1:0000").is_err());
    }
}
