//! MIT krb5 Credential Cache (FCC) v4 format — 纯二进制序列化/反序列化
//!
//! 格式规范来自 MIT krb5 源码 `krb5/src/lib/krb5/ccache/cccaches/fcc_v4.c`
//! 所有多字节整数均使用 **大端序 (big-endian)**，与 MIT 实现一致。

#![allow(dead_code)]

use std::io::{self, Write};

// ──────────────────────────────────
// 底层 I/O helpers
// ──────────────────────────────────

/// 写入 4 字节大端序 u32
fn write_be32<W: Write>(w: &mut W, v: u32) -> io::Result<()> {
    w.write_all(&v.to_be_bytes())
}

/// 从字节切片读取 4 字节大端序 u32（返回新偏移量）
fn read_be32(data: &[u8], off: &mut usize) -> io::Result<u32> {
    if *off + 4 > data.len() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short read (be32)"));
    }
    let v = u32::from_be_bytes([data[*off], data[*off+1], data[*off+2], data[*off+3]]);
    *off += 4;
    Ok(v)
}

/// 写入 2 字节大端序 u16
fn write_be16<W: Write>(w: &mut W, v: u16) -> io::Result<()> {
    w.write_all(&v.to_be_bytes())
}

/// 从字节切片读取 2 字节大端序 u16（返回新偏移量）
fn read_be16(data: &[u8], off: &mut usize) -> io::Result<u16> {
    if *off + 2 > data.len() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short read (be16)"));
    }
    let v = u16::from_be_bytes([data[*off], data[*off+1]]);
    *off += 2;
    Ok(v)
}

/// 写入 "计数 + 数据" 字段（MIT ccache 标准格式）
/// 4 字节大端序长度 + 原始字节
fn write_counted<W: Write>(w: &mut W, data: &[u8]) -> io::Result<()> {
    write_be32(w, data.len() as u32)?;
    w.write_all(data)
}

/// 从字节切片读取 "计数 + 数据" 字段（返回新偏移量）
fn read_counted(data: &[u8], off: &mut usize) -> io::Result<Vec<u8>> {
    let len = read_be32(data, off)? as usize;
    if *off + len > data.len() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short read (counted)"));
    }
    let buf = data[*off..*off+len].to_vec();
    *off += len;
    Ok(buf)
}

/// 从字节切片读取定长字节（返回新偏移量）
fn read_bytes<'a>(data: &'a [u8], off: &mut usize, n: usize) -> io::Result<&'a [u8]> {
    if *off + n > data.len() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short read (bytes)"));
    }
    let buf = &data[*off..*off+n];
    *off += n;
    Ok(buf)
}

// ──────────────────────────────────
// 核心数据结构
// ──────────────────────────────────

/// Kerberos principal（客户端/服务端标识）
///
/// 对应 MIT krb5 的 `krb5_principal` / ASN.1 `PrincipalName`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// name_type：1 = NT_PRINCIPAL，2 = NT_SRV_INST，等等
    pub name_type: u32,
    /// realm（领域），如 "XXX.COM"
    pub realm: String,
    /// 名称组件，如 ["hive"] 或 ["krbtgt", "XXX.COM"]
    pub components: Vec<String>,
}

impl Principal {
    pub fn new(name_type: u32, realm: &str, components: &[&str]) -> Self {
        Self {
            name_type,
            realm: realm.to_string(),
            components: components.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// 序列化 principal → MIT ccache 二进制格式
    pub fn build(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        // name_type (4 bytes BE)
        buf.extend_from_slice(&self.name_type.to_be_bytes());
        // num_components (4 bytes BE)
        buf.extend_from_slice(&(self.components.len() as u32).to_be_bytes());
        // realm (counted octet string)
        let realm_bytes = self.realm.as_bytes();
        buf.extend_from_slice(&(realm_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(realm_bytes);
        // components (每个都是 counted octet string)
        for comp in &self.components {
            let comp_bytes = comp.as_bytes();
            buf.extend_from_slice(&(comp_bytes.len() as u32).to_be_bytes());
            buf.extend_from_slice(comp_bytes);
        }
        buf
    }

    /// 从 MIT ccache 二进制格式反序列化
    pub fn parse(data: &[u8]) -> io::Result<(usize, Self)> {
        let mut off = 0;
        let name_type = read_be32(data, &mut off)?;
        let num_components = read_be32(data, &mut off)?;

        let realm_bytes = read_counted(data, &mut off)?;
        let realm = String::from_utf8_lossy(&realm_bytes).to_string();

        let mut components = Vec::new();
        for _ in 0..num_components {
            let comp_bytes = read_counted(data, &mut off)?;
            components.push(String::from_utf8_lossy(&comp_bytes).to_string());
        }

        Ok((off, Self { name_type, realm, components }))
    }
}

/// 密钥块（session key 的加密类型和密钥数据）
///
/// 对应 MIT krb5 的 `krb5_keyblock`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBlock {
    /// 加密类型（etype），如 18 = AES256_CTS_HMAC_SHA1_96
    pub enctype: u16,
    /// 密钥数据（原始字节）
    pub keyvalue: Vec<u8>,
}

impl KeyBlock {
    pub fn new(enctype: u16, keyvalue: Vec<u8>) -> Self {
        Self { enctype, keyvalue }
    }

    /// 序列化 keyblock → MIT ccache v4 二进制格式
    ///
    /// FCC v4 格式：**没有** etype 字段（与 v3 不同）
    /// - enctype：2 字节大端序
    /// - keyvalue_len：4 字节大端序
    /// - keyvalue：原始字节
    pub fn build(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        // enctype (2 bytes BE)
        buf.extend_from_slice(&self.enctype.to_be_bytes());
        // keyvalue (4-byte length + data)
        buf.extend_from_slice(&(self.keyvalue.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.keyvalue);
        buf
    }

    /// 从 MIT ccache v4 二进制格式反序列化
    pub fn parse(data: &[u8]) -> io::Result<(usize, Self)> {
        let mut off = 0;
        let enctype = read_be16(data, &mut off)?;
        let keyvalue = read_counted(data, &mut off)?;
        Ok((off, Self::new(enctype, keyvalue)))
    }
}

/// 时间戳集合（KerberosTime = Unix 时间戳，u32 大端序）
///
/// 对应 MIT krb5 的 `krb5_ticket_times`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Times {
    /// 认证时间（authtime），票据生效时间
    pub authtime: u32,
    /// 开始时间（starttime），通常为 0
    pub starttime: u32,
    /// 到期时间（endtime）
    pub endtime: u32,
    /// 可续期至（renew_till），不可续期时为 0
    pub renew_till: u32,
}

impl Times {
    pub fn new(authtime: u32, starttime: u32, endtime: u32, renew_till: u32) -> Self {
        Self { authtime, starttime, endtime, renew_till }
    }

    /// 序列化 times → MIT ccache 二进制格式
    ///
    /// 四个字段，**依次**写入 4 字节大端序 u32
    pub fn build(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&self.authtime.to_be_bytes());
        buf.extend_from_slice(&self.starttime.to_be_bytes());
        buf.extend_from_slice(&self.endtime.to_be_bytes());
        buf.extend_from_slice(&self.renew_till.to_be_bytes());
        buf
    }

    /// 从 MIT ccache 二进制格式反序列化
    pub fn parse(data: &[u8]) -> io::Result<(usize, Self)> {
        let mut off = 0;
        let authtime = read_be32(data, &mut off)?;
        let starttime = read_be32(data, &mut off)?;
        let endtime = read_be32(data, &mut off)?;
        let renew_till = read_be32(data, &mut off)?;
        Ok((off, Self::new(authtime, starttime, endtime, renew_till)))
    }
}

/// 主机地址（在 ccache 中通常为空）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAddr {
    pub addr_type: u16,
    pub addr_data: Vec<u8>,
}

impl HostAddr {
    fn build(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        write_be16(&mut buf, self.addr_type).unwrap();
        let _ = write_counted(&mut buf, &self.addr_data);
        buf
    }
    fn parse(data: &[u8], off: &mut usize) -> io::Result<Self> {
        let addr_type = read_be16(data, off)?;
        let addr_data = read_counted(data, off)?;
        Ok(Self { addr_type, addr_data })
    }
}

/// 认证数据（在 ccache 中通常为空）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthData {
    pub ad_type: u16,
    pub ad_data: Vec<u8>,
}

impl AuthData {
    fn build(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        write_be16(&mut buf, self.ad_type).unwrap();
        let _ = write_counted(&mut buf, &self.ad_data);
        buf
    }
    fn parse(data: &[u8], off: &mut usize) -> io::Result<Self> {
        let ad_type = read_be16(data, off)?;
        let ad_data = read_counted(data, off)?;
        Ok(Self { ad_type, ad_data })
    }
}

/// 单条 Kerberos 凭据（credential）
///
/// 对应 MIT krb5 的 `krb5_creds`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub client: Principal,
    pub server: Principal,
    pub key: KeyBlock,
    pub time: Times,
    /// 是否为 session key（通常为 0）
    pub is_skey: u8,
    /// 票据标志位（如 FORWARDABLE | RENEWABLE 等）
    pub tktflags: u32,
    /// 主机地址列表（通常为空）
    pub addrs: Vec<HostAddr>,
    /// 认证数据列表（通常为空）
    pub authdata: Vec<AuthData>,
    /// 票据（ASN.1 DER 编码的 Ticket）
    pub ticket: Vec<u8>,
    /// 第二票据（通常为空）
    pub second_ticket: Vec<u8>,
}

impl Credential {
    pub fn new(
        client: Principal,
        server: Principal,
        key: KeyBlock,
        time: Times,
        is_skey: u8,
        tktflags: u32,
        ticket: Vec<u8>,
    ) -> Self {
        Self {
            client,
            server,
            key,
            time,
            is_skey,
            tktflags,
            addrs: Vec::new(),
            authdata: Vec::new(),
            ticket,
            second_ticket: Vec::new(),
        }
    }

    /// 序列化 credential → MIT ccache v4 二进制格式
    pub fn build(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        // client principal
        buf.append(&mut self.client.build());
        // server principal
        buf.append(&mut self.server.build());
        // keyblock
        buf.append(&mut self.key.build());
        // times
        buf.append(&mut self.time.build());
        // is_skey (1 byte)
        buf.push(self.is_skey);
        // tktflags (4 bytes BE)
        buf.extend_from_slice(&self.tktflags.to_be_bytes());
        // addrs
        write_be32(&mut buf, self.addrs.len() as u32).unwrap();
        for addr in &self.addrs {
            buf.append(&mut addr.build());
        }
        // authdata
        write_be32(&mut buf, self.authdata.len() as u32).unwrap();
        for ad in &self.authdata {
            buf.append(&mut ad.build());
        }
        // ticket (counted octet string)
        let _ = write_counted(&mut buf, &self.ticket);
        // second_ticket (counted octet string)
        let _ = write_counted(&mut buf, &self.second_ticket);
        buf
    }

    /// 从 MIT ccache v4 二进制格式反序列化（传入 credential 数据部分，不含前面的 tag）
    pub fn parse(data: &[u8]) -> io::Result<(usize, Self)> {
        let mut off;

        let (used, client) = Principal::parse(data)?;
        off = used;
        let (used, server) = Principal::parse(&data[off..])?;
        off += used;
        let (used, key) = KeyBlock::parse(&data[off..])?;
        off += used;
        let (used, time) = Times::parse(&data[off..])?;
        off += used;

        let is_skey = *data.get(off).ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "short read (is_skey)"))?;
        off += 1;

        let tktflags = read_be32(data, &mut off)?;

        // addrs
        let num_addrs = read_be32(data, &mut off)? as usize;
        let mut addrs = Vec::new();
        for _ in 0..num_addrs {
            let addr = HostAddr::parse(data, &mut off)?;
            addrs.push(addr);
        }

        // authdata
        let num_authdata = read_be32(data, &mut off)? as usize;
        let mut authdata = Vec::new();
        for _ in 0..num_authdata {
            let ad = AuthData::parse(data, &mut off)?;
            authdata.push(ad);
        }

        // ticket
        let ticket = read_counted(data, &mut off)?;
        // second_ticket
        let second_ticket = read_counted(data, &mut off)?;

        Ok((off, Self {
            client,
            server,
            key,
            time,
            is_skey,
            tktflags,
            addrs,
            authdata,
            ticket,
            second_ticket,
        }))
    }
}

// ──────────────────────────────────
// CCache 顶层结构
// ──────────────────────────────────

/// MIT krb5 Credential Cache（FCC v4 格式）
///
/// 文件结构：
/// 1. 默认 principal（tag = 0x00000001）
/// 2. 0 或多个 credentials（每个 tag = 0x00000002）
///
/// 对应 MIT krb5 的 `krb5_ccache` 结构
#[derive(Debug, Clone)]
pub struct CCache {
    /// 默认 principal（文件所属用户）
    pub default_principal: Principal,
    /// 凭据列表（通常只有 1 条 TGT）
    pub credentials: Vec<Credential>,
}

impl CCache {
    pub fn new(default_principal: Principal, credentials: Vec<Credential>) -> Self {
        Self { default_principal, credentials }
    }

    /// 将 CCache 序列化为 MIT 兼容的二进制格式（FCC v4）
    pub fn build(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        // 1. FCC v4 文件头
        write_be16(&mut buf, 0x0504).unwrap();
        //    header_len = 12 (1 entry: tag(2)+len(2)+data(8))
        write_be16(&mut buf, 12).unwrap();

        // 2. Header entry: DeltaTime (tag=1, len=8, data=8bytes)
        write_be16(&mut buf, 0x0001).unwrap();
        write_be16(&mut buf, 8).unwrap();
        write_be32(&mut buf, 0).unwrap();  // time_offset
        write_be32(&mut buf, 0).unwrap();  // server_offset

        // 3. 默认 principal（无 tag）
        buf.append(&mut self.default_principal.build());
        // 4. credentials（无 tag）
        for cred in &self.credentials {
            buf.append(&mut cred.build());
        }
        buf
    }

    /// 从 MIT ccache 二进制格式反序列化
    pub fn parse(data: &[u8]) -> io::Result<(usize, Self)> {
        let mut off = 0;

        // 1. 读取版本号
        let tag = read_be16(data, &mut off)?;
        if tag != 0x0504 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported credentials cache format version: 0x{:04X}", tag),
            ));
        }

        // 2. 读取 header 长度，然后跳过整个 header 区域
        let header_len = read_be16(data, &mut off)?;
        off += header_len as usize;

        // 3. 读取默认 principal
        let (used, default_principal) = Principal::parse(&data[off..])?;
        off += used;

        // 4. 读取 credentials
        let mut credentials = Vec::new();
        while off < data.len() {
            let (used, cred) = Credential::parse(&data[off..])?;
            off += used;
            credentials.push(cred);
        }

        Ok((off, Self::new(default_principal, credentials)))
    }

    /// 便捷方法：直接将 CCache 写入文件
    pub fn write_to_file(&self, path: &str) -> io::Result<()> {
        let data = self.build();
        std::fs::write(path, data)
    }

    /// 便捷方法：直接从文件读取 CCache
    pub fn read_from_file(path: &str) -> io::Result<Self> {
        let data = std::fs::read(path)?;
        match Self::parse(&data) {
            Ok((_, ccache)) => Ok(ccache),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse ccache: {}", e),
            )),
        }
    }
}

// ──────────────────────────────────
// 单元测试
// ──────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_principal_build_parse_roundtrip() {
        let p = Principal::new(1, "XXX.COM", &["hive"]);
        let bytes = p.build();
        let (_, p2) = Principal::parse(&bytes).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn test_principal_build_parse_krbtgt() {
        let p = Principal::new(2, "XXX.COM", &["krbtgt", "XXX.COM"]);
        let bytes = p.build();
        let (_, p2) = Principal::parse(&bytes).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn test_keyblock_build_parse_roundtrip() {
        let k = KeyBlock::new(18, vec![0x01, 0x02, 0x03, 0x04]);
        let bytes = k.build();
        let (_, k2) = KeyBlock::parse(&bytes).unwrap();
        assert_eq!(k.enctype, k2.enctype);
        assert_eq!(k.keyvalue, k2.keyvalue);
    }

    #[test]
    fn test_times_build_parse_roundtrip() {
        let t = Times::new(1700000000, 0, 1700086400, 1700681600);
        let bytes = t.build();
        let (_, t2) = Times::parse(&bytes).unwrap();
        assert_eq!(t.authtime, t2.authtime);
        assert_eq!(t.endtime, t2.endtime);
    }

    #[test]
    fn test_credential_build_parse_roundtrip() {
        let client = Principal::new(1, "XXX.COM", &["hive"]);
        let server = Principal::new(2, "XXX.COM", &["krbtgt", "XXX.COM"]);
        let key = KeyBlock::new(18, vec![0u8; 32]);
        let time = Times::new(1700000000, 0, 1700086400, 1700681600);
        let ticket = vec![0x61, 0x82, 0x01, 0x00]; // 假 ticket 数据
        let cred = Credential::new(client, server, key, time, 0, 0x40c10000, ticket);
        let bytes = cred.build();
        let (_, cred2) = Credential::parse(&bytes).unwrap();
        assert_eq!(cred.client.realm, cred2.client.realm);
        assert_eq!(cred.server.name_type, cred2.server.name_type);
        assert_eq!(cred.key.enctype, cred2.key.enctype);
        assert_eq!(cred.tktflags, cred2.tktflags);
    }

    #[test]
    fn test_ccache_build_parse_roundtrip() {
        let default_principal = Principal::new(1, "XXX.COM", &["hive"]);
        let client = Principal::new(1, "XXX.COM", &["hive"]);
        let server = Principal::new(2, "XXX.COM", &["krbtgt", "XXX.COM"]);
        let key = KeyBlock::new(18, vec![0u8; 32]);
        let time = Times::new(1700000000, 0, 1700086400, 1700681600);
        let ticket = vec![0x61, 0x82, 0x01, 0x00];
        let cred = Credential::new(client, server, key, time, 0, 0x40c10000, ticket);
        let ccache = CCache::new(default_principal, vec![cred]);
        let bytes = ccache.build();
        let (_, ccache2) = CCache::parse(&bytes).unwrap();
        assert_eq!(ccache.default_principal.realm, ccache2.default_principal.realm);
        assert_eq!(ccache.credentials.len(), ccache2.credentials.len());
    }
}
