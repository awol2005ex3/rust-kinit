//! High-level Kerberos authentication integration.
//!
//! This module provides a convenient `KerberosAuthenticator` that ties together
//! the full authentication chain:
//!
//! 1. **TGT acquisition**: Request a Ticket-Granting Ticket from the KDC
//!    using the user's password or keytab.
//! 2. **Service ticket (TGS)**: Use the TGT to request a service ticket for
//!    a specific service principal name (SPN).
//! 3. **AP-REQ construction**: Build a Kerberos AP-REQ message from the
//!    service ticket, ready to be sent as a SASL GSSAPI token.
//!
//! The output AP-REQ bytes can be used directly with a `TSaslClientTransport`
//! in a Thrift client.

use crate::credentials::Credential;
use crate::messages::ApReqBuilder;
use crate::requesters::{TgsRequester, TgtRequester};
use ascii::AsciiString;
use kerberos_crypto::Key;
use std::net::IpAddr;

/// Options for configuring a `KerberosAuthenticator`.
#[derive(Debug, Clone)]
pub struct KerberosAuthOptions {
    /// Kerberos realm (e.g., "EXAMPLE.COM").
    pub realm: AsciiString,
    /// KDC server IP address.
    pub kdc_address: IpAddr,
    /// The KDC port (default: 88).
    pub kdc_port: Option<u16>,
    /// User principal name (e.g., "user" or "user@EXAMPLE.COM").
    pub username: AsciiString,
    /// User's Kerberos key (password, RC4 hash, or AES key).
    pub user_key: Key,
    /// Service principal name (e.g., "HTTP/server.example.com").
    pub service_principal: AsciiString,
    /// Whether to request mutual authentication in the AP-REQ.
    pub mutual_required: bool,
    /// Time offset in seconds to correct clock skew (KDC time - local time).
    /// Automatically detected from TGT authtime when set to 0.
    pub time_offset_secs: i64,
}

impl Default for KerberosAuthOptions {
    fn default() -> Self {
        // Use dummy values; user must override them.
        Self {
            realm: AsciiString::from_ascii("REALM.COM").unwrap(),
            kdc_address: IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            kdc_port: Some(88),
            username: AsciiString::from_ascii("user").unwrap(),
            user_key: Key::Secret(String::new()),
            service_principal: AsciiString::from_ascii("service/host").unwrap(),
            mutual_required: false,
            time_offset_secs: 0,
        }
    }
}

/// High-level Kerberos authenticator that performs the full
/// TGT → TGS → AP-REQ chain.
///
/// # Example
///
/// ```no_run
/// use kerbeiros::integration::{KerberosAuthenticator, KerberosAuthOptions};
/// use ascii::AsciiString;
/// use kerberos_crypto::Key;
/// use std::net::IpAddr;
/// use std::net::Ipv4Addr;
///
/// let options = KerberosAuthOptions {
///     realm: AsciiString::from_ascii("EXAMPLE.COM").unwrap(),
///     kdc_address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
///     username: AsciiString::from_ascii("alice").unwrap(),
///     user_key: Key::Secret("password123".to_string()),
///     service_principal: AsciiString::from_ascii("thrift/server.example.com").unwrap(),
///     ..Default::default()
/// };
///
/// let authenticator = KerberosAuthenticator::new(options);
/// let ap_req_bytes = authenticator.authenticate().unwrap();
///
/// // Use ap_req_bytes with TSaslClientTransport:
/// // let mut transport = TSaslClientTransport::new(stream, ap_req_bytes);
/// // transport.negotiate().unwrap();
/// ```
pub struct KerberosAuthenticator {
    options: KerberosAuthOptions,
}

impl KerberosAuthenticator {
    /// Create a new `KerberosAuthenticator` with the given options.
    pub fn new(options: KerberosAuthOptions) -> Self {
        Self { options }
    }

    /// Perform the full Kerberos authentication chain and return
    /// the DER-encoded AP-REQ bytes.
    ///
    /// # Steps
    ///
    /// 1. **TGT Request**: Sends AS-REQ to KDC, receives TGT credential.
    /// 2. **TGS Request**: Sends TGS-REQ with TGT to KDC, receives service
    ///    ticket credential.
    /// 3. **AP-REQ Build**: Constructs and encodes AP-REQ from the service
    ///    ticket credential.
    pub fn authenticate(&self) -> crate::Result<Vec<u8>> {
        // Step 1: Request TGT
        let tgt_requester = TgtRequester::new(
            self.options.realm.clone(),
            self.options.kdc_address,
        );
        let tgt_credential = tgt_requester
            .request(&self.options.username, Some(&self.options.user_key))?;

        // Step 2: Request service ticket using TGT
        let tgs_requester = TgsRequester::new(
            self.options.realm.clone(),
            self.options.kdc_address,
        );
        let service_credential = tgs_requester
            .request(&tgt_credential, &self.options.service_principal)?;

        // Step 3: Build AP-REQ for authentication
        let ap_req_options = crate::messages::ApReqOptions {
            mutual_required: self.options.mutual_required,
            use_session_key: false,
            gssapi_checksum: true,
            time_offset_secs: self.options.time_offset_secs,
            ..Default::default()
        };
        let ap_req_builder = ApReqBuilder::new(&service_credential)
            .with_options(ap_req_options);
        let ap_req_bytes = ap_req_builder.build()?;

        Ok(ap_req_bytes)
    }

    /// Perform the full Kerberos authentication chain and return
    /// both the AP-REQ bytes and the service credential.
    ///
    /// The service credential contains the session key and ticket details,
    /// which may be useful for session management.
    pub fn authenticate_full(&self) -> crate::Result<(Vec<u8>, Credential)> {
        let (ap_req, cred, _seq) = self.authenticate_full_with_seq()?;
        Ok((ap_req, cred))
    }

    /// Perform the full Kerberos authentication chain and return
    /// AP-REQ bytes, service credential, and the GSS initial seq number.
    ///
    /// The GSS init seq is needed to initialize the GSS engine for
    /// subsequent data exchange (wrap/unwrap).
    pub fn authenticate_full_with_seq(&self) -> crate::Result<(Vec<u8>, Credential, u32)> {
        // Step 1: Request TGT
        let tgt_requester = TgtRequester::new(
            self.options.realm.clone(),
            self.options.kdc_address,
        );
        let tgt_credential = tgt_requester
            .request(&self.options.username, Some(&self.options.user_key))?;

        // Step 2: Request service ticket using TGT
        let tgs_requester = TgsRequester::new(
            self.options.realm.clone(),
            self.options.kdc_address,
        );
        let service_credential = tgs_requester
            .request(&tgt_credential, &self.options.service_principal)?;

        // Step 3: Build AP-REQ with GSS checksum, extracting initial seq number
        let ap_req_options = crate::messages::ApReqOptions {
            mutual_required: self.options.mutual_required,
            use_session_key: false,
            gssapi_checksum: true,
            time_offset_secs: self.options.time_offset_secs,
            ..Default::default()
        };
        let ap_req_builder = ApReqBuilder::new(&service_credential)
            .with_options(ap_req_options);
        let (ap_req_bytes, gss_data) = ap_req_builder.build_with_gss_data()?;
        let gss_init_seq = gss_data.gss_initial_seq;

        Ok((ap_req_bytes, service_credential, gss_init_seq))
    }

    /// Like authenticate_full_with_seq but also returns the GSS subkey
    /// needed by Java JGSS-compatible GSS engines
    pub fn authenticate_full_with_seq_and_subkey(&self) -> crate::Result<(Vec<u8>, Credential, u32, u32, Vec<u8>, i32)> {
        // Step 1: Request TGT
        let tgt_requester = TgtRequester::new(
            self.options.realm.clone(),
            self.options.kdc_address,
        );
        let tgt_credential = tgt_requester
            .request(&self.options.username, Some(&self.options.user_key))?;

        // Step 2: Request service ticket using TGT
        let tgs_requester = TgsRequester::new(
            self.options.realm.clone(),
            self.options.kdc_address,
        );
        let service_credential = tgs_requester
            .request(&tgt_credential, &self.options.service_principal)?;

        // Step 3: Build AP-REQ with GSS checksum + subkey
        let ap_req_options = crate::messages::ApReqOptions {
            mutual_required: self.options.mutual_required,
            use_session_key: false,
            gssapi_checksum: true,
            time_offset_secs: self.options.time_offset_secs,
            ..Default::default()
        };
        let ap_req_builder = ApReqBuilder::new(&service_credential)
            .with_options(ap_req_options);
        let (ap_req_bytes, gss_data) = ap_req_builder.build_with_gss_data()?;

        Ok((ap_req_bytes, service_credential, gss_data.gss_initial_seq, gss_data.subkey_type as u32, gss_data.subkey, gss_data.subkey_type))
    }
}
