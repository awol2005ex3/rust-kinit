use crate::credentials::Credential;
use crate::error::*;
use crate::transporter::*;
use ascii::AsciiString;
use chrono::{Duration, Timelike, Utc};
use kerberos_asn1::{
    ApReq, Asn1Object, Authenticator, Checksum, EncryptedData,
    KrbError, PaData, PrincipalName, TgsRep,
    TgsReq,
};
use kerberos_constants::checksum_types::{
    HMAC_SHA1_96_AES128, HMAC_SHA1_96_AES256,
};
use kerberos_constants::key_usages::{
    KEY_USAGE_TGS_REP_ENC_PART_SESSION_KEY,
    KEY_USAGE_TGS_REQ_AUTHEN, KEY_USAGE_TGS_REQ_AUTHEN_CKSUM,
};
use kerberos_constants::kdc_options::{FORWARDABLE, RENEWABLE, RENEWABLE_OK};
use kerberos_constants::pa_data_types::{PA_PAC_REQUEST, PA_TGS_REQ};
use kerberos_constants::principal_names::NT_PRINCIPAL;
use kerberos_crypto::{
    checksum_hmac_md5, checksum_sha_aes, new_kerberos_cipher,
    AesSizes,
};
use rand::Rng;
use std::net::IpAddr;
/// Possible responses to a TGS-REQ request
#[derive(Debug, PartialEq)]
pub enum TgsReqResponse {
    KrbError(KrbError),
    TgsRep(TgsRep),
}

/// Sends TGS-REQ requests to the KDC to obtain a service ticket
/// using a previously obtained TGT credential.
///
/// # Examples
///
/// ```no_run
/// use kerbeiros::*;
/// use ascii::AsciiString;
/// use std::net::*;
/// use kerberos_crypto::Key;
///
/// // First get a TGT
/// let realm = AsciiString::from_ascii("CONTOSO.COM").unwrap();
/// let kdc_address = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
/// let username = AsciiString::from_ascii("Bob").unwrap();
/// let user_key = Key::Secret("S3cr3t".to_string());
///
/// let mut tgt_requester = TgtRequester::new(realm.clone(), kdc_address);
/// let tgt_credential = tgt_requester.request(&username, Some(&user_key)).unwrap();
///
/// // Use TGT to get a service ticket for the thrift service
/// let service_principal = AsciiString::from_ascii("thrift/server.contoso.com").unwrap();
/// let mut tgs_requester = TgsRequester::new(realm, kdc_address);
/// let service_credential = tgs_requester.request(
///     &tgt_credential,
///     &service_principal,
/// ).unwrap();
/// ```
pub struct TgsRequester {
    realm: AsciiString,
    transporter: Box<dyn Transporter>,
    etypes: Vec<i32>,
}

impl TgsRequester {
    pub fn new(realm: AsciiString, kdc_address: IpAddr) -> Self {
        return Self {
            realm,
            transporter: new_transporter(kdc_address, TransportProtocol::TCP),
            // Order matters: AES256 first so KDC prefers it for session key
            etypes: vec![
                kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96,
                kerberos_constants::etypes::AES128_CTS_HMAC_SHA1_96,
                kerberos_constants::etypes::RC4_HMAC,
            ],
        };
    }

    pub fn set_transport_protocol(
        &mut self,
        transport_protocol: TransportProtocol,
    ) {
        // Re-wrap the transporter with new protocol
        // This is a limitation since we don't have access to the original IpAddr
        // Users should use ::new() to create with a different protocol
        let _ = transport_protocol;
    }

    /// Request service ticket and also return the raw TGS-REQ bytes (for debugging).
    pub fn request_with_raw(
        &self,
        tgt_credential: &Credential,
        service_principal: &AsciiString,
    ) -> Result<(Credential, Vec<u8>)> {
        let raw_tgs_req = self.build_tgs_req(tgt_credential, service_principal)?;
        let tgs_rep = self.send_tgs_req_raw(tgt_credential, &raw_tgs_req)?;

        match tgs_rep {
            TgsReqResponse::KrbError(krb_error) => {
                return Err(Error::KrbErrorResponse(krb_error))?;
            }
            TgsReqResponse::TgsRep(tgs_rep) => {
                let credential = self.extract_credential_from_tgs_rep(
                    tgt_credential,
                    tgs_rep,
                )?;
                return Ok((credential, raw_tgs_req));
            }
        }
    }

    pub fn request(
        &self,
        tgt_credential: &Credential,
        service_principal: &AsciiString,
    ) -> Result<Credential> {
        let tgs_rep = self.send_tgs_req(tgt_credential, service_principal)?;

        match tgs_rep {
            TgsReqResponse::KrbError(krb_error) => {
                return Err(Error::KrbErrorResponse(krb_error))?;
            }
            TgsReqResponse::TgsRep(tgs_rep) => {
                return self.extract_credential_from_tgs_rep(
                    tgt_credential,
                    tgs_rep,
                );
            }
        }
    }

    /// Like send_tgs_req but takes pre-built TGS-REQ bytes.
    fn send_tgs_req_raw(
        &self,
        _tgt_credential: &Credential,
        raw_tgs_req: &[u8],
    ) -> Result<TgsReqResponse> {
        let raw_response = self.transporter.request_and_response(raw_tgs_req)?;

        match KrbError::parse(&raw_response) {
            Ok((_, krb_error)) => {
                return Ok(TgsReqResponse::KrbError(krb_error));
            }
            Err(_) => {
                let (_, tgs_rep) = TgsRep::parse(&raw_response)?;
                return Ok(TgsReqResponse::TgsRep(tgs_rep));
            }
        }
    }

    fn send_tgs_req(
        &self,
        tgt_credential: &Credential,
        service_principal: &AsciiString,
    ) -> Result<TgsReqResponse> {
        let raw_tgs_req =
            self.build_tgs_req(tgt_credential, service_principal)?;
        self.send_tgs_req_raw(tgt_credential, &raw_tgs_req)
    }

    fn build_tgs_req(
        &self,
        tgt_credential: &Credential,
        service_principal: &AsciiString,
    ) -> Result<Vec<u8>> {
        // Build KDC-REQ-BODY for TGS-REQ
        // Split SPN string into components on '/' and strip '@REALM' suffix
        let spn_str = service_principal.as_str();
        // Remove @REALM suffix if present (e.g. "hive/bd-pr-nn1@GHAC.COM" -> "hive/bd-pr-nn1")
        let spn_clean = spn_str.split('@').next().unwrap_or(spn_str);
        let parts: Vec<&str> = spn_clean.split('/').collect();
        
        if parts.is_empty() {
            return Err(Error::NotAvailableData("Empty service principal".into()));
        }
        
        // Use NT_PRINCIPAL (value=1) to match MIT krb5 behavior.
        // MIT krb5 gss_accept_sec_context checks the ticket's sname name_type
        // against the acceptor's expected name_type (NT_PRINCIPAL). If they
        // don't match, the server (Hive) rejects the GSS context.
        // The KDC copies the name_type from the TGS-REQ body sname into the
        // returned ticket's sname, so we must send NT_PRINCIPAL here.
        let mut sname = PrincipalName::new(
            NT_PRINCIPAL,
            parts[0].to_string(),
        );
        for part in &parts[1..] {
            sname.push((*part).to_string());
        }

        let mut kdc_req_body = kerberos_asn1::KdcReqBody::default();
        kdc_req_body.kdc_options =
            kerberos_asn1::KdcOptions::from(FORWARDABLE | RENEWABLE | RENEWABLE_OK);
        // Include client IP address in TGS-REQ - MIT krb5 always does this,
        // and Microsoft KDC requires it to include the PAC in the service ticket.
        // Without addresses, KDC returns a ticket without authorization data (PAC).
        use kerberos_asn1::HostAddress;
        // Hard-code our machine's actual IP (10.110.149.18)
        let local_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 110, 149, 18));
        // including local IP in TGS-REQ addresses
        let addr = HostAddress {
            addr_type: 2,
            address: vec![10, 110, 149, 18],
        };
        kdc_req_body.addresses = Some(vec![addr]);
        kdc_req_body.realm = self.realm.clone().into();
        kdc_req_body.sname = Some(sname);
        kdc_req_body.till = Utc::now()
            .checked_add_signed(Duration::weeks(20 * 52))
            .unwrap()
            .into();
        kdc_req_body.rtime = Some(
            Utc::now()
                .checked_add_signed(Duration::weeks(20 * 52))
                .unwrap()
                .into(),
        );
        kdc_req_body.nonce = rand::thread_rng().r#gen::<u32>();
        for etype in self.etypes.iter() {
            kdc_req_body.etypes.push(*etype);
        }

        // Build PA-TGS-REQ = AP-REQ (with TGT ticket + encrypted authenticator)
        let ap_req_bytes =
            self.build_ap_req_for_tgs(tgt_credential, &kdc_req_body)?;

        let pa_tgs_req = PaData::new(PA_TGS_REQ, ap_req_bytes);

        // Build TGS-REQ
        let mut tgs_req = TgsReq::default();
        tgs_req.req_body = kdc_req_body;
        // Also request PAC (authorization data) in the service ticket.
        // Microsoft KDC requires PA-PAC-REQUEST in TGS-REQ to include
        // the PAC. Without it, the service ticket won't have the PAC,
        // causing Hive to reject the GSS context.
        let pa_pac_req = PaData::new(PA_PAC_REQUEST,
            kerberos_asn1::KerbPaPacRequest::new(true).build());

        tgs_req.padata = Some(vec![pa_tgs_req, pa_pac_req]);

        let tgs_bytes = tgs_req.build();
        // TGS-REQ built
        return Ok(tgs_bytes);
    }

    fn build_ap_req_for_tgs(
        &self,
        tgt_credential: &Credential,
        req_body: &kerberos_asn1::KdcReqBody,
    ) -> Result<Vec<u8>> {
        let session_key = tgt_credential.key();
        let etype = session_key.keytype;

        let cipher = new_kerberos_cipher(etype)?;

        // Compute checksum of KDC-REQ-BODY (for Authenticator.cksum)
        let req_body_bytes = req_body.build();
        let checksum_data = self.compute_checksum(
            etype,
            &session_key.keyvalue,
            KEY_USAGE_TGS_REQ_AUTHEN_CKSUM,
            &req_body_bytes,
        );

        // Build Authenticator with the correct checksum
        let now = Utc::now();
        let checksum_type = match etype {
            kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96 => {
                HMAC_SHA1_96_AES256
            }
            kerberos_constants::etypes::AES128_CTS_HMAC_SHA1_96 => {
                HMAC_SHA1_96_AES128
            }
            _ => HMAC_SHA1_96_AES256,
        };

        let authenticator = Authenticator {
            authenticator_vno: 5,
            crealm: tgt_credential.crealm().clone(),
            cname: tgt_credential.cname().clone(),
            cksum: Some(Checksum {
                cksumtype: checksum_type,
                checksum: checksum_data,
            }),
            cusec: (now.nanosecond() / 1000) as i32,
            ctime: now.into(),
            subkey: None,
            seq_number: None,
            authorization_data: None,
        };

        let raw_authenticator = authenticator.build();

        // Encrypt authenticator with TGS session key (KEY_USAGE_TGS_REQ_AUTHEN)
        let encrypted_auth = cipher.encrypt(
            &session_key.keyvalue,
            KEY_USAGE_TGS_REQ_AUTHEN,
            &raw_authenticator,
        );

        let enc_auth = EncryptedData::new(etype, None, encrypted_auth);

        // Build AP-REQ
        let ap_req = ApReq {
            pvno: 5,
            msg_type: 14,
            ap_options: kerberos_asn1::ApOptions::default(),
            ticket: tgt_credential.ticket().clone(),
            authenticator: enc_auth,
        };

        return Ok(ap_req.build());
    }

    fn compute_checksum(
        &self,
        etype: i32,
        key: &[u8],
        key_usage: i32,
        data: &[u8],
    ) -> Vec<u8> {
        match etype {
            kerberos_constants::etypes::RC4_HMAC => {
                checksum_hmac_md5(key, key_usage, data)
            }
            kerberos_constants::etypes::AES128_CTS_HMAC_SHA1_96 => {
                checksum_sha_aes(key, key_usage, data, &AesSizes::Aes128)
            }
            _ => {
                // Default to AES256
                checksum_sha_aes(key, key_usage, data, &AesSizes::Aes256)
            }
        }
    }

    fn extract_credential_from_tgs_rep(
        &self,
        tgt_credential: &Credential,
        tgs_rep: TgsRep,
    ) -> Result<Credential> {
        // Decrypt the enc_part using TGS session key
        let session_key = tgt_credential.key();
        let cipher = new_kerberos_cipher(tgs_rep.enc_part.etype)?;

        let plaintext = cipher.decrypt(
            &session_key.keyvalue,
            KEY_USAGE_TGS_REP_ENC_PART_SESSION_KEY,
            &tgs_rep.enc_part.cipher,
        )?;

        // Parse as EncTgsRepPart
        let (_, enc_tgs_rep_part) =
            kerberos_asn1::EncTgsRepPart::parse(&plaintext)?;

        // Map to credential (EncTgsRepPart -> EncAsRepPart via From trait)
        // Also print the ticket's own enc_part (this goes into AP-REQ)
        // TGS-REP processed

        
        let credential = Credential::new(
            tgs_rep.crealm,
            tgs_rep.cname,
            tgs_rep.ticket,
            kerberos_asn1::EncAsRepPart::from(enc_tgs_rep_part),
        );

        return Ok(credential);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use kerberos_asn1::{EncryptedData, Ticket, PrincipalName};
    use std::net::Ipv4Addr;

    #[should_panic(expected = "NetworkError")]
    #[test]
    fn test_request_network_error() {
        let tgs_requester = TgsRequester::new(
            AsciiString::from_ascii("TEST.COM").unwrap(),
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        );

        // Create a minimal fake TGT credential
        let ticket = Ticket::new(
            "TEST.COM".to_string(),
            PrincipalName::new(NT_SRV_INST, "krbtgt".into()),
            EncryptedData::new(
                kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96,
                None,
                vec![],
            ),
        );
        let enc_key = kerberos_asn1::EncryptionKey::new(
            kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96,
            vec![0u8; 32],
        );
        let enc_as_rep = kerberos_asn1::EncAsRepPart {
            key: enc_key,
            ..Default::default()
        };
        let fake_credential = Credential::new(
            "TEST.COM".to_string(),
            PrincipalName::new(
                kerberos_constants::principal_names::NT_PRINCIPAL,
                "user".into(),
            ),
            ticket,
            enc_as_rep,
        );

        tgs_requester
            .request(
                &fake_credential,
                &AsciiString::from_ascii("test/svc").unwrap(),
            )
            .unwrap();
    }
}
