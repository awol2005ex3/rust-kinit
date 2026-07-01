//! Builder for AP-REQ messages used in Kerberos authentication.
//!
//! AP-REQ is sent from client to server (or KDC in PA-TGS-REQ) to
//! authenticate using a service ticket and session key.

use crate::credentials::Credential;
use crate::error::*;
use chrono::{Duration, Timelike, Utc};
use rand;
use kerberos_asn1::{
    ApReq, Asn1Object, Authenticator, EncryptedData,
};
use kerberos_constants::key_usages::{KEY_USAGE_AP_REQ_AUTHEN};
use kerberos_crypto::{
    new_kerberos_cipher,
};


/// GSS checksum data extracted from AP-REQ building
pub struct GssChecksumData {
    pub gss_initial_seq: u32,
    pub subkey: Vec<u8>,
    pub subkey_type: i32,
}

/// Options for building an AP-REQ
#[derive(Debug, Clone)]
pub struct ApReqOptions {
    /// Whether to request mutual authentication (server must reply with AP-REP)
    pub mutual_required: bool,
    /// Whether to use session key instead of ticket key
    pub use_session_key: bool,
    /// Whether to include a GSSAPI checksum (cksumtype=0x8003) in the Authenticator.
    /// Some Java GSSAPI implementations are strict about this.
    pub gssapi_checksum: bool,
    /// Time offset in seconds to add to Utc::now() for the authenticator's ctime.
    /// Use this to correct for clock skew between client and KDC/server.
    /// Positive = client clock behind server, negative = client ahead.
    pub time_offset_secs: i64,
}

impl Default for ApReqOptions {
    fn default() -> Self {
        Self {
            mutual_required: true,
            use_session_key: false,
            gssapi_checksum: true,
            time_offset_secs: 0,
        }
    }
}

/// Builds an AP-REQ message for Kerberos authentication.
///
/// The AP-REQ contains:
/// - The service ticket obtained from KDC via TGS
/// - An Authenticator encrypted with the session key
///
/// This is the final step in Kerberos authentication before
/// the application protocol (e.g., Thrift SASL) takes over.
///
/// # Example
///
/// ```no_run
/// use kerbeiros::*;
/// use ascii::AsciiString;
///
/// // Assume we have a service credential from TgsRequester
/// // let service_credential: Credential = ...;
/// // let ap_req_bytes = ApReqBuilder::new(&service_credential)
/// //     .build()
/// //     .unwrap();
/// ```
pub struct ApReqBuilder<'a> {
    credential: &'a Credential,
    options: ApReqOptions,
}

impl<'a> ApReqBuilder<'a> {
    /// Create a new AP-REQ builder for the given service credential.
    ///
    /// The `credential` should be obtained via `TgsRequester::request()`
    /// and contains the service ticket and session key.
    pub fn new(credential: &'a Credential) -> Self {
        Self {
            credential,
            options: ApReqOptions::default(),
        }
    }

    /// Set options for this AP-REQ
    pub fn with_options(mut self, options: ApReqOptions) -> Self {
        self.options = options;
        self
    }

    /// Build the AP-REQ message as raw bytes.
    ///
    /// Returns the DER-encoded AP-REQ which can be used:
    /// - In a PA-TGS-REQ padata for TGS requests
    /// - As the initial token in a GSS-API/SASL Kerberos exchange
    pub fn build(&self) -> Result<Vec<u8>> {
        self.build_impl().map(|(bytes, _)| bytes)
    }

    /// Build the AP-REQ message and return GSS initial sequence number.
    /// Returns (DER-encoded AP-REQ, GSS initial seq number).
    pub fn build_with_gss_data(&self) -> Result<(Vec<u8>, GssChecksumData)> {
        self.build_impl()
    }

    fn build_impl(&self) -> Result<(Vec<u8>, GssChecksumData)> {
        let session_key = self.credential.key();
        let etype = session_key.keytype;

        let gss_seq: u32 = rand::random::<u32>();
        // Java JGSS useSubkey=true: generate random AES session key as subkey
        // OpenJDK InitSecContextToken creates subkey for every AP-REQ
        let subkey_type = etype.max(17); // at least AES128
        let subkey_len = match subkey_type { 18 => 32, _ => 16 };
        let subkey_bytes: Vec<u8> = (0..subkey_len).map(|_| rand::random::<u8>()).collect();
        eprintln!("[apreq] Generated subkey etype={}, bytes={:02x?}", subkey_type, subkey_bytes);
        let gssapi_checksum: Option<kerberos_asn1::Checksum> = if self.options.gssapi_checksum {
            // MIT krb5 make_gss_checksum() for GSS_C_NO_CHANNEL_BINDINGS (null):
            // Format (RFC 4121 §4.1.1.1, MIT krb5 src/lib/gssapi/krb5/make_checksum.c):
            //   [0x10, 0x00, 0x00, 0x00]  ← GSS_C_AF_EXT (address family extension)
            //                              / NOT a length field! Indicates no channel bindings
            //   [16 bytes zeros]            ← channel binding hash (GSS_C_NO_CHANNEL_BINDINGS)
            //   [gss_flags (4B LE)]         ← e.g. 0x0E = MUTUAL|REPLAY|SEQUENCE
            //   [seq_number (4B LE)]
            // Total: 28 bytes.
            // CRITICAL: OpenJDK OverloadedChecksum checks:
            //   checksumBytes[0..3] == {0x10, 0x00, 0x00, 0x00}
            //   If first byte is 0x00, OpenJDK throws "Incorrect checksum"!
            let mut v = Vec::with_capacity(28);
            v.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);   // GSS_C_AF_EXT
            v.extend_from_slice(&[0u8; 16]);                    // 16B zeros (no channel bindings)
            let gss_flags: u32 = if self.options.mutual_required { 0x0000000E } else { 0x0000000C };
            v.extend_from_slice(&gss_flags.to_le_bytes());      // flags (LE)
            println!("[apreq] GSS initial seq_number={}", gss_seq);
            v.extend_from_slice(&gss_seq.to_le_bytes());         // seq_number (LE)
            Some(kerberos_asn1::Checksum {
                cksumtype: 0x8003,
                checksum: v,
            })
        } else {
            None
        };
        let mut now = Utc::now();
        if self.options.time_offset_secs != 0 {
            now = now + chrono::Duration::seconds(self.options.time_offset_secs);
        }
        let authenticator = Authenticator {
            authenticator_vno: 5,
            crealm: self.credential.crealm().clone(),
            cname: self.credential.cname().clone(),
            cksum: gssapi_checksum,
            cusec: (now.nanosecond() / 1000) as i32,
            ctime: now.into(),
            subkey: Some(kerberos_asn1::EncryptionKey { keytype: subkey_type as i32, keyvalue: subkey_bytes.clone() }),
                seq_number: if self.options.gssapi_checksum { Some(gss_seq) } else { None },
            authorization_data: None,
        };

        let raw_authenticator = authenticator.build();
        eprintln!("[apreq] Authenticator plaintext ({} bytes): {:02x?}", raw_authenticator.len(), raw_authenticator);
        eprintln!("[apreq] Session key etype={}, bytes={:02x?}", etype, session_key.keyvalue);
        eprintln!("[apreq] key_usage=AP_REQ_AUTHEN({})", KEY_USAGE_AP_REQ_AUTHEN);

        // Encrypt authenticator with the service session key
        let cipher = new_kerberos_cipher(etype)?;
        let encrypted_auth = cipher.encrypt(
            &session_key.keyvalue,
            KEY_USAGE_AP_REQ_AUTHEN,
            &raw_authenticator,
        );
        eprintln!("[apreq] cipher after encrypt ({} bytes): {:02x?}", encrypted_auth.len(), encrypted_auth);

        let enc_auth = EncryptedData::new(etype, None, encrypted_auth);

        // Build AP-options
        let mut ap_options_val: u32 = 0;
        if self.options.mutual_required {
            ap_options_val |= kerberos_constants::ap_options::MUTUAL_REQUIRED;
        }
        if self.options.use_session_key {
            ap_options_val |= kerberos_constants::ap_options::USE_SESSION_KEY;
        }
        let ap_options = kerberos_asn1::ApOptions::from(ap_options_val);

        // Build AP-REQ
        let ap_req = ApReq {
            pvno: 5,
            msg_type: 14,
            ap_options,
            ticket: self.credential.ticket().clone(),
            authenticator: enc_auth,
        };

        return Ok((ap_req.build(), GssChecksumData { gss_initial_seq: gss_seq, subkey: subkey_bytes, subkey_type }));
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use kerberos_asn1::{PrincipalName, Ticket, EncryptedData, EncryptionKey};
    use kerberos_constants::principal_names::NT_SRV_INST;
    use kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96;

    #[test]
    fn test_ap_req_build_simple() {
        // Create a minimal service credential for AP-REQ
        let ticket = Ticket::new(
            "TEST.COM".to_string(),
            PrincipalName::new(NT_SRV_INST, "test/svc".into()),
            EncryptedData::new(AES256_CTS_HMAC_SHA1_96, None, vec![]),
        );

        let enc_key = EncryptionKey::new(
            AES256_CTS_HMAC_SHA1_96,
            vec![0u8; 32],
        );

        let enc_as_rep = kerberos_asn1::EncAsRepPart {
            key: enc_key,
            ..Default::default()
        };

        let credential = Credential::new(
            "TEST.COM".to_string(),
            PrincipalName::new(
                kerberos_constants::principal_names::NT_PRINCIPAL,
                "user".into(),
            ),
            ticket,
            enc_as_rep,
        );

        let result = ApReqBuilder::new(&credential).build();
        assert!(result.is_ok());

        let ap_req_bytes = result.unwrap();
        // Verify it can be parsed back as ApReq
        let (_, parsed) = ApReq::parse(&ap_req_bytes).unwrap();
        assert_eq!(parsed.pvno, 5);
        assert_eq!(parsed.msg_type, 14);
    }
}
