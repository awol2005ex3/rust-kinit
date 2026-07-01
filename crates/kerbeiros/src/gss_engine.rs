// GSS-API Kerberos v5 message protection
//
// KEY FINDING FROM MIC ANALYSIS:
// Server MIC header: 050401ff000c00 00000000 3f183e34
//                    TOK_WRAP|SGN_ALG|FILLER|EC||RRC|SND_SEQ
// SND_SEQ is at [12..16], SGN_ALG=0x01
// BUT! The server may use a DIFFERENT KEY for computing its checksum
// (subkey from AP-REP, or derived differently)
//
// Meanwhile, our WRAP token may need SGN_ALG=0x00 (SSPI) which is what
// Python SSPI produces. The server MIC uses 0x01 which is RFC 4121 format.
// The server rejects our WRAP because GSS unwrap fails at SASL layer.
use kerberos_crypto::{checksum_sha_aes, AesSizes};

const TOK_WRAP: [u8; 2] = [0x05, 0x04];
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

    /// GSS_Wrap: RFC 4121 format matching server MIC
    /// 
    /// Server MIC header: 05 04 01 ff 00 0c 00 00 00 00 00 00 [SND_SEQ@12..16]
    /// SND_SEQ at bytes[12..16], SGN_ALG=0x01, EC=0x0000, RRC=0x0000
    /// Checksum per RFC 4121 §4.2.4: EC||RRC||header||data||0xFF*pad||0*16
    /// key_usage: 22=acceptor, 23=initiator
    pub fn wrap_with_ku(&mut self, plaintext: &[u8], key_usage: i32) -> std::io::Result<Vec<u8>> {
        let seq = self.seq_num;
        self.seq_num = self.seq_num.wrapping_add(1);
        let data_len = plaintext.len();
        let pad_len = if data_len == 0 { 0 } else { (16 - (data_len % 16)) % 16 };

        let mut header = [0u8; GSS_HEADER_LEN];
        header[0..2].copy_from_slice(&TOK_WRAP);    // 05 04
        header[2] = 0x01;                              // SGN_ALG RFC 4121
        header[3] = 0xff;                              // SEAL_ALG none
        header[4..6].copy_from_slice(&[0x00, 0x0c]);   // FILLER
        header[12..16].copy_from_slice(&seq.to_be_bytes()); // SND_SEQ at [12..16]

        // RFC 4121 checksum input: EC||RRC||header||data||0xFF*pad||0*16
        let mut ci = Vec::new();
        ci.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // EC||RRC = 0
        ci.extend_from_slice(&header[..]);                 // header 16B
        ci.extend_from_slice(plaintext);                   // data
        if pad_len > 0 {
            ci.extend(std::iter::repeat(0xFFu8).take(pad_len));
        }
        ci.extend_from_slice(&[0u8; 16]);                  // 0*16 suffix

        let cksum = checksum_sha_aes(
            &self.session_key, key_usage, &ci, &self.aes_sizes,
        );

        let mut token = Vec::with_capacity(GSS_HEADER_LEN + data_len + CKSUM_LEN);
        token.extend_from_slice(&header);
        token.extend_from_slice(plaintext);
        token.extend_from_slice(&cksum);
        Ok(token)
    }

    /// Wrapper: wrap with default key_usage=22 (acceptor)
    pub fn wrap(&mut self, plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
        self.wrap_with_ku(plaintext, 22)
    }

    /// Wrap with initiator key_usage=23 (WRAP without encryption)
    pub fn wrap_initiator(&mut self, plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
        self.wrap_with_ku(plaintext, 23)
    }

    /// Wrap with SEAL key_usage=25 (WRAP with encryption, initiator)
    #[allow(dead_code)]
    pub fn wrap_seal_initiator(&mut self, plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
        self.wrap_with_ku(plaintext, 25)
    }
    
    /// Java AES GSS_Wrap: SGN_ALG=0x11, SEAL_ALG=0x10, FILLER=0xffff
    pub fn wrap_java(&mut self, plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
        let seq = self.seq_num;
        self.seq_num = self.seq_num.wrapping_add(1);
        let data_len = plaintext.len();
        let pad_len = (16 - (data_len % 16)) % 16;

        let mut header = [0u8; GSS_HEADER_LEN];
        header[0..2].copy_from_slice(&TOK_WRAP);
        header[2] = 0x11;          // SGN_ALG HMAC SHA1 AES
        header[3] = 0x10;          // SEAL_ALG AES
        header[4..6].copy_from_slice(&[0xff, 0xff]); // FILLER
        header[6..8].copy_from_slice(&[0x00, pad_len as u8]); // EC = 0, RRC = padding count
        // Actually RRC = right rotate count = 0
        header[8..10].copy_from_slice(&[0x00, 0x00]); // RRC = 0
        header[12..16].copy_from_slice(&seq.to_be_bytes()); // SND_SEQ at [12..16]

        // RFC 4121 checksum: EC||RRC||header||data||0xFF*pad||0*16
        let mut ci = Vec::new();
        ci.extend_from_slice(&[0x00, pad_len as u8, 0x00, 0x00]); // EC||RRC (big-endian)
        ci.extend_from_slice(&header[..]);
        ci.extend_from_slice(plaintext);
        if pad_len > 0 {
            ci.extend(std::iter::repeat(0xFFu8).take(pad_len));
        }
        ci.extend_from_slice(&[0u8; 16]);

        let cksum = checksum_sha_aes(
            &self.session_key, 22, &ci, &self.aes_sizes,
        );

        let mut token = Vec::with_capacity(GSS_HEADER_LEN + data_len + CKSUM_LEN);
        token.extend_from_slice(&header);
        token.extend_from_slice(plaintext);
        token.extend_from_slice(&cksum);
        Ok(token)
    }
    
    pub fn wrap_rfc4121(&mut self, plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
        let seq = self.seq_num;

        let data_len = plaintext.len();
        let pad_len = (16 - (data_len % 16)) % 16;

        let mut header = [0u8; GSS_HEADER_LEN];
        header[0..2].copy_from_slice(&TOK_WRAP);
        header[2] = 0x01;          // SGN_ALG RFC 4121
        header[3] = 0xff;          // SEAL_ALG none
        header[4..6].copy_from_slice(&[0x00, 0x0c]); // FILLER
        header[12..16].copy_from_slice(&seq.to_be_bytes()); // SND_SEQ at [12..16]

        let mut ci = Vec::new();
        ci.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // EC||RRC
        ci.extend_from_slice(&header[..]);
        ci.extend_from_slice(plaintext);
        if pad_len > 0 {
            ci.extend(std::iter::repeat(0xFFu8).take(pad_len));
        }
        ci.extend_from_slice(&[0u8; 16]);
        
        eprintln!("  [wrap] RFC4121 k22 cksum_input={}B", ci.len());

        let cksum = checksum_sha_aes(
            &self.session_key, 22, &ci, &self.aes_sizes,
        );

        let mut token = Vec::with_capacity(GSS_HEADER_LEN + data_len + CKSUM_LEN);
        token.extend_from_slice(&header);
        token.extend_from_slice(plaintext);
        token.extend_from_slice(&cksum);
        Ok(token)
    }

    pub fn unwrap(&mut self, token: &[u8]) -> std::io::Result<Vec<u8>> {
        if token.len() < GSS_HEADER_LEN + CKSUM_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("GSS token too short: {} bytes", token.len()),
            ));
        }

        let data_end = token.len() - CKSUM_LEN;
        let header = &token[..GSS_HEADER_LEN];
        let plaintext = &token[GSS_HEADER_LEN..data_end];
        let received_cksum = &token[data_end..];
        let data_len = plaintext.len();
        let pad_len = (16 - (data_len % 16)) % 16;

        eprintln!("  [unwrap] h={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            header[0],header[1],header[2],header[3],header[4],header[5],header[6],header[7],
            header[8],header[9],header[10],header[11],header[12],header[13],header[14],header[15]);
        eprintln!("  [unwrap] s10={} s12={} data={}B", 
            u32::from_be_bytes([header[10],header[11],header[12],header[13]]),
            u32::from_be_bytes([header[12],header[13],header[14],header[15]]),
            data_len);
        eprintln!("  [unwrap] cksum_recv={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            received_cksum[0],received_cksum[1],received_cksum[2],received_cksum[3],
            received_cksum[4],received_cksum[5],received_cksum[6],received_cksum[7],
            received_cksum[8],received_cksum[9],received_cksum[10],received_cksum[11]);

        for usage in &[22, 23, 24, 25, 17] {
            for seq_bytestart in &[10, 12] {
                let seq_pos = *seq_bytestart;
                let seq = u32::from_be_bytes([
                    header[seq_pos], header[seq_pos+1], 
                    header[seq_pos+2], header[seq_pos+3]
                ]);
                
                // Format A: EC||RRC(4) || header(16) || data || 0xFF*pad || 0*16
                let ecrr: [u8; 4] = [header[6], header[7], header[8], header[9]];
                for &use_ecrr in &[true, false] {
                    let mut ci = Vec::new();
                    if use_ecrr { ci.extend_from_slice(&ecrr); }
                    ci.extend_from_slice(&header[..]);
                    ci.extend_from_slice(plaintext);
                    if pad_len > 0 { ci.extend(std::iter::repeat(0xFFu8).take(pad_len)); }
                    ci.extend_from_slice(&[0u8; 16]);
                    let c = checksum_sha_aes(&self.session_key, *usage, &ci, &self.aes_sizes);
                    if c == received_cksum {
                        return Ok(plaintext.to_vec());
                    }
                    // Debug first combo
                    if *usage == 22 && seq_pos == 12 && use_ecrr {
                        eprintln!("  [unwrap] k22_s12_ecrr: computed={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                            c[0],c[1],c[2],c[3],c[4],c[5],c[6],c[7],c[8],c[9],c[10],c[11]);
                    }
                }
                
                // Format B: seq(4) || header(16) || data || 0*12 (SSPI)
                let mut ci = Vec::new();
                ci.extend_from_slice(&seq.to_be_bytes());
                ci.extend_from_slice(&header[..]);
                ci.extend_from_slice(plaintext);
                ci.extend_from_slice(&[0u8; CKSUM_LEN]);
                let c = checksum_sha_aes(&self.session_key, *usage, &ci, &self.aes_sizes);
                if c == received_cksum {
                    return Ok(plaintext.to_vec());
                }
                
                // Format C: header(16) || data || 0*12
                let mut ci2 = Vec::new();
                ci2.extend_from_slice(&header[..]);
                ci2.extend_from_slice(plaintext);
                ci2.extend_from_slice(&[0u8; CKSUM_LEN]);
                let c2 = checksum_sha_aes(&self.session_key, *usage, &ci2, &self.aes_sizes);
                if c2 == received_cksum {
                    return Ok(plaintext.to_vec());
                }
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData, "GSS checksum verification failed"))
    }

    pub fn seq_num(&self) -> u32 { self.seq_num }
    pub fn reset_seq_num(&mut self, seq: u32) { self.seq_num = seq; }
}
