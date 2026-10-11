//! Access-link generation for client onboarding.
//!
//! Builds a minimal client TOML and wraps it into a
//! `mirage://import?v=1&name=...&config=...` link that the Android app imports.

use std::net::IpAddr;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ipnet::IpNet;
use serde::Serialize;

use crate::error::{MirageError, Result};

/// Resolved values needed to build a client config + access link.
#[derive(Clone, Debug)]
pub struct ShareLinkParams {
    /// Label shown in the app (percent-encoded into the link)
    pub name: String,
    /// Public host/IP clients dial
    pub host: String,
    /// Public port clients dial
    pub port: u16,
    pub username: String,
    pub password: String,
    /// PEM certificates to trust (self-signed servers)
    pub trusted_certificates: Vec<String>,
    /// Whether the server offers QUIC on the same port
    pub quic: bool,
    pub camouflage_mode: String,
    pub target_sni: String,
    /// Only the first entry is used (the client uses the first short id)
    pub short_ids: Vec<String>,
    pub jls_password: Option<String>,
    pub jls_iv: Option<String>,
    pub inner_key: Option<String>,
    pub inner_encryption: bool,
    /// CIDR strings
    pub routes: Vec<String>,
    /// IP address strings
    pub dns_servers: Vec<String>,
}

#[derive(Serialize)]
struct LinkClient {
    server: LinkServer,
    authentication: LinkAuth,
    transport: LinkTransport,
    camouflage: LinkCamouflage,
    obfuscation: LinkObfuscation,
    network: LinkNetwork,
    log: LinkLog,
}

#[derive(Serialize)]
struct LinkServer {
    host: String,
    port: u16,
}

#[derive(Serialize)]
struct LinkAuth {
    username: String,
    password: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    trusted_certificates: Vec<String>,
}

#[derive(Serialize)]
struct LinkTransport {
    protocols: Vec<&'static str>,
}

#[derive(Serialize)]
struct LinkCamouflage {
    mode: String,
    target_sni: String,
    short_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jls_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jls_iv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inner_key: Option<String>,
}

#[derive(Serialize)]
struct LinkObfuscation {
    inner_encryption: bool,
}

#[derive(Serialize)]
struct LinkNetwork {
    routes: Vec<String>,
    dns_servers: Vec<String>,
}

#[derive(Serialize)]
struct LinkLog {
    level: &'static str,
}

/// Percent-encodes a string (RFC 3986 unreserved characters are kept).
pub fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Builds the client TOML and the access link. Returns `(toml, link)`.
pub fn build_share_link(p: &ShareLinkParams) -> Result<(String, String)> {
    for r in &p.routes {
        r.parse::<IpNet>()
            .map_err(|e| MirageError::config_error(format!("Invalid route '{r}': {e}")))?;
    }
    for d in &p.dns_servers {
        d.parse::<IpAddr>()
            .map_err(|e| MirageError::config_error(format!("Invalid DNS server '{d}': {e}")))?;
    }

    let cfg = LinkClient {
        server: LinkServer {
            host: p.host.clone(),
            port: p.port,
        },
        authentication: LinkAuth {
            username: p.username.clone(),
            password: p.password.clone(),
            trusted_certificates: p.trusted_certificates.clone(),
        },
        transport: LinkTransport {
            protocols: if p.quic {
                vec!["udp", "tcp"]
            } else {
                vec!["tcp"]
            },
        },
        camouflage: LinkCamouflage {
            mode: p.camouflage_mode.clone(),
            target_sni: p.target_sni.clone(),
            short_ids: p.short_ids.iter().take(1).cloned().collect(),
            jls_password: p.jls_password.clone(),
            jls_iv: p.jls_iv.clone(),
            inner_key: p.inner_key.clone(),
        },
        obfuscation: LinkObfuscation {
            inner_encryption: p.inner_encryption,
        },
        network: LinkNetwork {
            routes: p.routes.clone(),
            dns_servers: p.dns_servers.clone(),
        },
        log: LinkLog { level: "info" },
    };

    let toml_str = toml::to_string(&cfg)
        .map_err(|e| MirageError::config_error(format!("Failed to serialize client config: {e}")))?;

    let link = format!(
        "mirage://import?v=1&name={}&config={}",
        percent_encode(&p.name),
        URL_SAFE_NO_PAD.encode(toml_str.as_bytes())
    );
    Ok((toml_str, link))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ClientConfig, TransportProtocol};
    use figment::providers::{Format, Toml};
    use figment::Figment;

    fn params() -> ShareLinkParams {
        ShareLinkParams {
            name: "My VPN".into(),
            host: "vpn.example.com".into(),
            port: 8443,
            username: "alice".into(),
            password: "pw".into(),
            trusted_certificates: vec![],
            quic: true,
            camouflage_mode: "mirage".into(),
            target_sni: "www.microsoft.com".into(),
            short_ids: vec!["abcd1234".into(), "0011".into()],
            jls_password: Some("jp".into()),
            jls_iv: Some("iv".into()),
            inner_key: Some("ik".into()),
            inner_encryption: true,
            routes: vec!["0.0.0.0/0".into(), "::/0".into()],
            dns_servers: vec!["1.1.1.1".into(), "2606:4700:4700::1111".into()],
        }
    }

    fn parse(toml: &str) -> ClientConfig {
        Figment::new()
            .merge(Toml::string(toml))
            .extract()
            .expect("generated TOML must parse as ClientConfig")
    }

    #[test]
    fn toml_parses_into_client_config() {
        let p = params();
        let (toml, _) = build_share_link(&p).unwrap();
        let c = parse(&toml);
        assert_eq!(c.server.host, p.host);
        assert_eq!(c.server.port, p.port);
        assert_eq!(c.authentication.username, p.username);
        assert_eq!(c.authentication.password, p.password);
        assert_eq!(c.camouflage.short_ids, vec!["abcd1234".to_string()]);
        assert_eq!(
            c.transport.protocols,
            vec![TransportProtocol::Udp, TransportProtocol::Tcp]
        );
        assert!(c.obfuscation.inner_encryption);
        assert_eq!(c.camouflage.inner_key.as_deref(), Some("ik"));
        assert_eq!(c.network.routes.len(), 2);
        assert_eq!(c.network.dns_servers.len(), 2);
    }

    #[test]
    fn tcp_only_when_no_quic() {
        let mut p = params();
        p.quic = false;
        let (toml, _) = build_share_link(&p).unwrap();
        assert_eq!(parse(&toml).transport.protocols, vec![TransportProtocol::Tcp]);
    }

    #[test]
    fn link_decodes_back_to_toml() {
        let (toml, link) = build_share_link(&params()).unwrap();
        let prefix = "mirage://import?v=1&name=My%20VPN&config=";
        assert!(link.starts_with(prefix), "{link}");
        let b64 = &link[prefix.len()..];
        assert!(!b64.contains('=') && !b64.contains('+') && !b64.contains('/'));
        let decoded = URL_SAFE_NO_PAD.decode(b64).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), toml);
    }

    #[test]
    fn special_characters_are_escaped() {
        let mut p = params();
        p.password = "a\"b\\c'd\ne#f=g&h é".into();
        p.name = "Wörk & Play/100%".into();
        p.trusted_certificates = vec!["-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n".into()];
        let (toml, link) = build_share_link(&p).unwrap();
        let c = parse(&toml);
        assert_eq!(c.authentication.password, p.password);
        assert_eq!(c.authentication.trusted_certificates, p.trusted_certificates);
        assert!(link.contains("name=W%C3%B6rk%20%26%20Play%2F100%25&"), "{link}");
    }

    #[test]
    fn rejects_bad_routes_and_dns() {
        let mut p = params();
        p.routes = vec!["nonsense".into()];
        assert!(build_share_link(&p).is_err());
        let mut p = params();
        p.dns_servers = vec!["nope".into()];
        assert!(build_share_link(&p).is_err());
    }
}
