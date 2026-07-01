//! Implement functions that can be useful to support the main library functionality.

use crate::{Error, Result};
use ascii::AsciiString;
use dns_lookup;
use std::net::IpAddr;

/// Get the local machine's non-loopback IPv4 address.
/// Uses an UDP connect to determine the actual network interface IP.
pub fn get_local_ip() -> Option<IpAddr> {
    use std::net::UdpSocket;
    // Connect to a known external address to determine which local interface
    // would be used to reach it. We connect a UDP socket (no real traffic).
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("10.110.194.23:88").is_ok() {
            if let Ok(local_addr) = sock.local_addr() {
                let ip = local_addr.ip();
                if ip.is_ipv4() && !ip.is_loopback() {
                    return Some(ip);
                }
            }
        }
    }
    None
}

/// Resolve the address of the KDC from the name of the realm.
///
/// # Errors
/// Returns [`Error`](../error/struct.Error.html) if it is not possible to resolve the domain name or the resolution does not include any IP address.
pub fn resolve_realm_kdc(realm: &AsciiString) -> Result<IpAddr> {
    let ips = dns_lookup::lookup_host(realm.as_ref())
        .map_err(|_| Error::NameResolutionError(realm.to_string()))?;

    if ips.is_empty() {
        return Err(Error::NameResolutionError(realm.to_string()));
    }

    return Ok(ips[0]);
}
