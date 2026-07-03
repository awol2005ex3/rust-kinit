// GSS-API Kerberos v5 message protection — JDK V2 format (CDP/Hadoop JGSS)
//
// JDK MessageTokenHeader (16 bytes):
//   [0-1]: TOK_ID (0x0504=WRAP, 0x0404=MIC)
//   [2]:   Flags (1=SENDER_IS_ACCEPTOR, 2=CONFIDENTIAL, 4=ACCEPTOR_SUBKEY)
//   [3]:   FILLER = 0xff
//   [4-5]: EC (initially 0, set to 0x000c = checksum length for non-conf WRAP)
//   [6-7]: RRC (0)
//   [8-15]: SND_SEQ (64-bit big-endian)
//
// Checksum CI (from getChecksum):
//   buf = [data(0..len)][header(16B)]
//   header[4..7] cleared (EC + RRC set to 0)
//   Aes256.calculateChecksum(key, key_usage, buf, 0, total)
//
// key_usage: 22=acceptor_seal, 23=acceptor_sign, 24=initiator_seal, 25=initiator_sign
use kerberos_crypto::{checksum_sha_aes, AesSizes};

const TOK_WRAP: u16 = 0x0504;
const FLAG_SENDER_IS_ACCEPTOR: u8 = 0x01;
const FILLER: u8 = 0xff;
const GSS_HEADER_LEN: usize = 16;
const CKSUM_LEN: usize = 12;

pub struct KerberosGssEngine {
    session_key: Vec<u8>,
    aes_sizes: AesSizes,
    seq_num: u32,
}

impl KerberosGssEngine {
    pub fn new(session_key: Vec<u8>, key_type: i32) -> Self {
        let aes_sizes = match key_type {
            18 => AesSizes::Aes256,
            17 => AesSizes::Aes128,
            _ => AesSizes::Aes256,
        };
        KerberosGssEngine { session_key, aes_sizes, seq_num: 0 }
    }

    pub fn new_with_seq(session_key: Vec<u8>, key_type: i32, seq_num: u32) -> Self {
        let aes_sizes = match key_type {
            18 => AesSizes::Aes256,
            17 => AesSizes::Aes128,
            _ => AesSizes::Aes256,
        };
        KerberosGssEngine { session_key, aes_sizes, seq_num }
    }

    /// Build a JDK-V2 WRAP token (no encryption, auth-only).
    pub fn wrap_with_ku_java(&mut self, plaintext: &[u8], key_usage: i32) -> std::io::Result<Vec<u8>> {
        let seq = self.seq_num;
        self.seq_num = self.seq_num.wrapping_add(1);

        // Build header per JDK MessageTokenHeader(WRAP_ID_v2, false)
        let mut hdr = [0u8; GSS_HEADER_LEN];
        hdr[0] = (TOK_WRAP >> 8) as u8;          // 0x05
        hdr[1] = TOK_WRAP as u8;                  // 0x04
        // flags: initiator → 0, acceptor → 0x01
        let is_acceptor = key_usage == 22 || key_usage == 23;
        if is_acceptor { hdr[2] = FLAG_SENDER_IS_ACCEPTOR; }
        hdr[3] = FILLER;                           // 0xff
        // bytes[4-7]: EC+RRC = 0 (set EC after checksum)
        // bytes[8-15]: SND_SEQ (64-bit big endian)
        hdr[8..12].copy_from_slice(&[0u8; 4]);    // high 32 bits of seq
        hdr[12..16].copy_from_slice(&seq.to_be_bytes());

        // CI = data || header with bytes[4-7] cleared
        let mut ci_hdr = hdr;
        ci_hdr[4] = 0; ci_hdr[5] = 0;
        ci_hdr[6] = 0; ci_hdr[7] = 0;
        let ci: Vec<u8> = plaintext.iter()
            .chain(ci_hdr.iter())
            .copied()
            .collect();
        let cksum = checksum_sha_aes(&self.session_key, key_usage, &ci, &self.aes_sizes);

        // Set EC = checksum length (0x000c) for non-conf WRAP
        hdr[4] = 0x00;
        hdr[5] = 0x0c;

        // Wire: [16B header][payload][12B checksum]
        let mut token = Vec::with_capacity(GSS_HEADER_LEN + plaintext.len() + CKSUM_LEN);
        token.extend_from_slice(&hdr);
        token.extend_from_slice(plaintext);
        token.extend_from_slice(&cksum);
        Ok(token)
    }

    /// GSS_Wrap: default to acceptor seal
    pub fn wrap(&mut self, plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
        self.wrap_with_ku_java(plaintext, 22)
    }

    /// Unwrap a JDK V2 WRAP token: try all 4 key_usage values
    pub fn unwrap(&mut self, token: &[u8]) -> std::io::Result<Vec<u8>> {
        if token.len() < GSS_HEADER_LEN + CKSUM_LEN {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                format!("token too short: {} bytes", token.len())));
        }

        let data_end = token.len() - CKSUM_LEN;
        let hdr = &token[..GSS_HEADER_LEN];
        let plaintext = &token[GSS_HEADER_LEN..data_end];
        let received_cksum = &token[data_end..];

        // CI = data || header[..16] with bytes[4-7] cleared
        let mut ci_hdr: [u8; GSS_HEADER_LEN] = [0; GSS_HEADER_LEN];
        ci_hdr.copy_from_slice(hdr);
        ci_hdr[4] = 0; ci_hdr[5] = 0;
        ci_hdr[6] = 0; ci_hdr[7] = 0;
        let ci: Vec<u8> = plaintext.iter()
            .chain(ci_hdr.iter())
            .copied()
            .collect();

        // Try ku 22, 24, 23, 25 (acceptor/initiator seal/sign)
        let key_usages = [22i32, 24i32, 23i32, 25i32];
        for &ku in &key_usages {
            let c = checksum_sha_aes(&self.session_key, ku, &ci, &self.aes_sizes);
            if c == received_cksum {
                eprintln!("  [unwrap] MATCH ku={}! (header={:02x?})", ku, &hdr[..4]);
                return Ok(plaintext.to_vec());
            }
        }

        // Debug dump
        eprintln!("  [unwrap] KEY={}", hex_str(&self.session_key));
        eprintln!("  [unwrap] HDR={}", hex_str(hdr));
        eprintln!("  [unwrap] DATA={}", hex_str(plaintext));
        eprintln!("  [unwrap] CI={}", hex_str(&ci));
        eprintln!("  [unwrap] CKSUM_RCVD={}", hex_str(received_cksum));
        Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
            "GSS checksum verification failed"))
    }

    pub fn seq_num(&self) -> u32 { self.seq_num }
    pub fn reset_seq_num(&mut self, seq: u32) { self.seq_num = seq; }
}

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect::<Vec<_>>().join("")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_wrap_unwrap_roundtrip() {
        let key = vec![0x25u8; 32];
        let mut eng = KerberosGssEngine::new_with_seq(key.clone(), 18, 100);
        let data = b"hello world";
        let wrapped = eng.wrap(data).unwrap();
        let mut eng2 = KerberosGssEngine::new_with_seq(key.clone(), 18, 100);
        let unwrapped = eng2.unwrap(&wrapped).unwrap();
        assert_eq!(&unwrapped, data);
    }

    #[test]
    fn test_wrap_initiator() {
        let key = vec![0x25u8; 32];
        let mut eng = KerberosGssEngine::new_with_seq(key.clone(), 18, 42);
        let data = b"test init";
        let wrapped = eng.wrap_with_ku_java(data, 24).unwrap();
        let mut eng2 = KerberosGssEngine::new_with_seq(key.clone(), 18, 42);
        let unwrapped = eng2.unwrap(&wrapped).unwrap();
        assert_eq!(&unwrapped, data);
    }
}
