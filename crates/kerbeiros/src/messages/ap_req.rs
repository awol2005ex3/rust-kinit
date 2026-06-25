//! Builder for AP-REQ messages used in Kerberos authentication.
//!
//! AP-REQ is sent from client to server (or KDC in PA-TGS-REQ) to
//! authenticate using a service ticket and session key.

use crate::credentials::Credential;
use crate::error::*;
use chrono::{Timelike, Utc};
use kerberos_asn1::{
    ApReq, Asn1Object, Authenticator, EncryptedData,
};
use kerberos_constants::key_usages::KEY_USAGE_AP_REQ_AUTHEN;
use kerberos_crypto::{
    new_kerberos_cipher,
};


/// Options for building an AP-REQ
#[derive(Debug, Clone)]
pub struct ApReqOptions {
    /// Whether to request mutual authentication (server must reply with AP-REP)
    pub mutual_required: bool,
    /// Whether to use session key instead of ticket key
    pub use_session_key: bool,
}

impl Default for ApReqOptions {
    fn default() -> Self {
        Self {
            mutual_required: true,
            use_session_key: false,
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
        let session_key = self.credential.key();
        let etype = session_key.keytype;

        // Build the authenticator
        let now = Utc::now();
        let authenticator = Authenticator {
            authenticator_vno: 5,
            crealm: self.credential.crealm().clone(),
            cname: self.credential.cname().clone(),
            cksum: None,
            cusec: (now.nanosecond() / 1000) as i32,
            ctime: now.into(),
            subkey: None,
            seq_number: None,
            authorization_data: None,
        };

        let raw_authenticator = authenticator.build();

        // Encrypt authenticator with the service session key
        let cipher = new_kerberos_cipher(etype)?;
        let encrypted_auth = cipher.encrypt(
            &session_key.keyvalue,
            KEY_USAGE_AP_REQ_AUTHEN,
            &raw_authenticator,
        );

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

        return Ok(ap_req.build());
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
