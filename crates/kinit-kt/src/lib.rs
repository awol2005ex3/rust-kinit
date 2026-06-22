// kinit-kt: Rust 实现的 kinit -kt
// 核心库：读取 keytab → 请求 TGT → 返回 ccache 数据
//
// 用法（作为库）：
//   let ccache = kinit_kt::request_tgt(keytab_path, principal, krb5_ini_path)?;
//   std::fs::write("krb5cc_test", ccache)?;

use mit_krb5_ccache::{Credential as MitCred, Principal as MitPrincipal, KeyBlock as MitKeyBlock, Times as MitTimes, CCache as MitCCache};
use kerberos_keytab::Keytab;
use kerberos_crypto::Key;
use kerberos_constants::etypes;
use kerbeiros::TgtRequester;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use kerberos_asn1::{Asn1Object, KerberosTime, TicketFlags};



// ---------- 公共 API ----------

/// 从 keytab 获取 TGT，返回 ccache 文件内容（FCCACHE v4 格式）
///
/// # 参数
/// - `keytab_path`: keytab 文件路径
/// - `principal`: Kerberos principal，格式 `name@REALM` 或 `name/instance@REALM`
/// - `krb5_ini_path`: 可选，krb5.ini 路径（用于解析 KDC 地址）
///
/// # 返回
/// - `Ok(Vec<u8>)`: ccache 文件内容，可直接写入文件
/// - `Err(String)`: 错误信息
pub fn request_tgt(
    keytab_path: &str,
    principal: &str,
    krb5_ini_path: Option<&str>,
) -> Result<Vec<u8>, String> {
    let (principal_name, realm) = parse_principal(principal)?;

    // 读取 keytab
    let keytab_data = std::fs::read(keytab_path)
        .map_err(|e| format!("读取 keytab 失败: {}", e))?;
    let (_remaining, keytab) = Keytab::parse(&keytab_data)
        .map_err(|e| format!("keytab 解析失败: {:?}", e))?;
    let key = find_key_in_keytab(&keytab, &principal_name, &realm)?;
    let etype = key.etypes()[0];

    // 解析 KDC 地址（传 clone，保留 realm 供后面使用）
    let kdc_addr = resolve_kdc(&realm, krb5_ini_path)?;

    // 构造请求
    let username = ascii::AsciiString::from_ascii(principal_name.clone())
        .map_err(|_| format!("principal 名不是有效 ASCII: {}", principal_name))?;
    let realm_ascii = ascii::AsciiString::from_ascii(realm.clone())
        .map_err(|_| format!("realm 不是有效 ASCII: {}", realm))?;

    let mut requester = TgtRequester::new(realm_ascii, kdc_addr);
    requester
        .set_etype(etype)
        .map_err(|e| format!("设置 etype 失败: {:?}", e))?;

    // 请求 TGT
    println!("\n=== {} ===\n[request_tgt] principal={}, keytab={}\n", chrono::Utc::now(), principal, keytab_path);

    let credential = requester
        .request(&username, Some(&key))
        .map_err(|e| {
            let msg = format!("获取 TGT 失败: {:?}", e);
            println!("{}\n\n", msg);
            msg
        })?;

    println!("[request_tgt] 成功获取 credential\n");

    // 转换为 MIT ccache 格式并序列化为 Vec<u8>
    let buf = build_mit_ccache(&credential);
    Ok(buf)
}


/// 将 kerbeiros::Credential 转换为 MIT krb5 ccache 格式（使用 mit-krb5-ccache）
fn build_mit_ccache(cred: &kerbeiros::credentials::Credential) -> Vec<u8> {
    // 1. Client principal
    let cname = cred.cname();
    let client = MitPrincipal::new(
        cname.name_type as u32,
        cred.crealm(),
        &cname.name_string.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
    );

    // 2. Server principal
    let sname = cred.sname();
    let server = MitPrincipal::new(
        sname.name_type as u32,
        cred.srealm(),
        &sname.name_string.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
    );

    // 3. KeyBlock
    let key = cred.key();
    let key_block = MitKeyBlock::new(
        key.keytype as u16,
        key.keyvalue.clone(),
    );

    // 4. Times
    let authtime = kerberos_time_to_unix(cred.authtime());
    let starttime = cred.starttime().map(kerberos_time_to_unix).unwrap_or(0);
    let endtime = kerberos_time_to_unix(cred.endtime());
    let renew_till = cred.renew_till().map(kerberos_time_to_unix).unwrap_or(0);
    let times = MitTimes::new(authtime, starttime, endtime, renew_till);

    // 5. Ticket flags
    let tktflags = ticket_flags_to_u32(cred.flags());

    // 6. Ticket (ASN.1 DER)
    let ticket = cred.ticket().build();

    // 7. Build credential
    let mit_cred = MitCred::new(
        client.clone(), server, key_block, times,
        0,  // is_skey
        tktflags,
        ticket,
    );

    // 8. Build CCache
    let ccache = MitCCache::new(client, vec![mit_cred]);
    ccache.build()
}

/// KerberosTime → Unix timestamp (u32)
fn kerberos_time_to_unix(t: &KerberosTime) -> u32 {
    t.timestamp() as u32
}

/// TicketFlags → u32 位掩码
fn ticket_flags_to_u32(_f: &TicketFlags) -> u32 {
    // 暂时返回常用值：FORWARDABLE | RENEWABLE | PRE_AUTHENT
    // 正确做法：从 TicketFlags 的 BIT STRING 中取出位
    0x40c10000
}


pub fn request_tgt_credential(
    keytab_path: &str,
    principal: &str,
    krb5_ini_path: Option<&str>,
) -> Result<kerbeiros::credentials::Credential, String> {
    let (principal_name, realm) = parse_principal(principal)?;

    let keytab_data = std::fs::read(keytab_path)
        .map_err(|e| format!("读取 keytab 失败: {}", e))?;
    let (_remaining, keytab) = Keytab::parse(&keytab_data)
        .map_err(|e| format!("keytab 解析失败: {:?}", e))?;
    let key = find_key_in_keytab(&keytab, &principal_name, &realm)?;
    let etype = key.etypes()[0];

    let kdc_addr = resolve_kdc(&realm, krb5_ini_path)?;

    let username = ascii::AsciiString::from_ascii(principal_name.clone())
        .map_err(|_| format!("principal 名不是有效 ASCII: {}", principal_name))?;
    let realm_ascii = ascii::AsciiString::from_ascii(realm.clone())
        .map_err(|_| format!("realm 不是有效 ASCII: {}", realm))?;

    let mut requester = TgtRequester::new(realm_ascii, kdc_addr);
    requester
        .set_etype(etype)
        .map_err(|e| format!("设置 etype 失败: {:?}", e))?;

    let credential = requester
        .request(&username, Some(&key))
        .map_err(|e| {
            let msg = format!("获取 TGT 失败: {:?}", e);
            println!("{}\n\n", msg);
            msg
        })?;

    Ok(credential)
}

// ---------- 内部实现 ----------

fn parse_principal(principal: &str) -> Result<(String, String), String> {
    let parts: Vec<&str> = principal.split('@').collect();
    if parts.len() != 2 {
        Err(format!(
            "principal 格式错误，应为 name@REALM: {}",
            principal
        ))
    } else {
        Ok((parts[0].to_string(), parts[1].to_string()))
    }
}

fn find_key_in_keytab(
    keytab: &Keytab,
    principal_name: &str,
    realm: &str,
) -> Result<Key, String> {
    let mut best: Option<&kerberos_keytab::KeytabEntry> = None;
    let mut best_priority: i32 = 999;
    let mut best_kvno: u32 = 0;  // 同 etype 内优先选 kvno 最大的（0 表示未匹配）

    // [DEBUG] 打印所有匹配的 keytab 条目
    println!(
        "[find_key_in_keytab] 查找 principal={}@{}, 共 {} 个条目\n",
        principal_name, realm, keytab.entries.len()
    );

    for (i, entry) in keytab.entries.iter().enumerate() {
        let entry_realm = String::from_utf8_lossy(&entry.realm.data);
        let entry_name: Vec<String> = entry
            .components
            .iter()
            .map(|c| String::from_utf8_lossy(&c.data).into_owned())
            .collect();
        let entry_name_str = entry_name.join("/");

        let matched = entry_realm == realm && entry_name_str == principal_name;
        if matched {
            let keytype_name = match entry.key.keytype as i32 {
                etypes::AES256_CTS_HMAC_SHA1_96 => "AES256",
                etypes::AES128_CTS_HMAC_SHA1_96 => "AES128",
                etypes::RC4_HMAC => "RC4",
                _ => "UNKNOWN",
            };
            println!(
                "[find_key_in_keytab] [{}] MATCH: keytype={}({}), kvno={:?}, key_len={}\n",
                i, entry.key.keytype, keytype_name, entry.vno, entry.key.keyvalue.len()
            );
        }

        if entry_realm == realm && entry_name_str == principal_name {
            let priority = match entry.key.keytype as i32 {
                etypes::AES256_CTS_HMAC_SHA1_96 => 1,
                etypes::AES128_CTS_HMAC_SHA1_96 => 2,
                etypes::RC4_HMAC => 3,
                _ => 999,
            };
            let kvno = entry.vno.unwrap_or(0);
            // 选 key 规则：etype 优先级高者优先；同 etype 时 kvno 大者优先（最新 key）
            if priority < best_priority || (priority == best_priority && kvno > best_kvno) {
                best = Some(entry);
                best_priority = priority;
                best_kvno = kvno;
            }
        }
    }

    let entry = best.ok_or_else(|| {
        format!(
            "keytab 中未找到匹配 {}@{} 的条目",
            principal_name, realm
        )
    })?;

    println!(
        "[find_key_in_keytab] 选中: keytype={}, kvno={:?}, key_len={}\n",
        entry.key.keytype, entry.vno, entry.key.keyvalue.len()
    );

    keytab_entry_to_key(entry)
}

fn keytab_entry_to_key(
    entry: &kerberos_keytab::KeytabEntry,
) -> Result<Key, String> {
    match entry.key.keytype as i32 {
        etypes::AES256_CTS_HMAC_SHA1_96 => {
            if entry.key.keyvalue.len() != 32 {
                return Err(format!(
                    "AES256 key 长度错误: {}（期望32）",
                    entry.key.keyvalue.len()
                ));
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&entry.key.keyvalue);
            Ok(Key::AES256Key(key_bytes))
        }
        etypes::AES128_CTS_HMAC_SHA1_96 => {
            if entry.key.keyvalue.len() != 16 {
                return Err(format!(
                    "AES128 key 长度错误: {}（期望16）",
                    entry.key.keyvalue.len()
                ));
            }
            let mut key_bytes = [0u8; 16];
            key_bytes.copy_from_slice(&entry.key.keyvalue);
            Ok(Key::AES128Key(key_bytes))
        }
        etypes::RC4_HMAC => {
            if entry.key.keyvalue.len() != 16 {
                return Err(format!(
                    "RC4 key 长度错误: {}（期望16）",
                    entry.key.keyvalue.len()
                ));
            }
            let mut key_bytes = [0u8; 16];
            key_bytes.copy_from_slice(&entry.key.keyvalue);
            Ok(Key::RC4Key(key_bytes))
        }
        _ => Err(format!("不支持的 keytype: {}", entry.key.keytype)),
    }
}

/// 解析 KDC 地址（realm 为 &str，不获取所有权）
fn resolve_kdc(realm: &str, krb5_ini_path: Option<&str>) -> Result<IpAddr, String> {
    // 1. 显式传入的路径
    if let Some(path) = krb5_ini_path {
        if Path::new(path).exists() {
            if let Ok(addr) = parse_krb5_ini(path, realm) {
                return Ok(addr);
            }
        }
    }

    // 2. 环境变量 KRB5_CONFIG
    if let Ok(val) = std::env::var("KRB5_CONFIG") {
        if Path::new(&val).exists() {
            if let Ok(addr) = parse_krb5_ini(&val, realm) {
                return Ok(addr);
            }
        }
    }

    // 3. 常见默认路径
    let default_paths = [
        "C:\\ProgramData\\MIT\\Kerberos5\\krb5.ini",
        "C:\\MIT\\Kerberos\\krb5.ini",
    ];
    for path in default_paths.iter() {
        if Path::new(path).exists() {
            if let Ok(addr) = parse_krb5_ini(path, realm) {
                return Ok(addr);
            }
        }
    }

    // 4. 回退：DNS 解析 realm 名
    dns_resolve(realm)
}

/// 解析 MIT krb5.ini 格式（支持 [realms] 区块内 `REALM = {` 语法）
fn parse_krb5_ini(path: &str, realm: &str) -> Result<IpAddr, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("读取 {} 失败: {}", path, e))?;

    let realm_upper = realm.to_uppercase();
    let mut in_realms = false;
    let mut in_realm_block = false;

    for raw_line in content.lines() {
        let line = raw_line.trim();

        if line.starts_with('[') && line.ends_with(']') {
            let section = line[1..line.len() - 1].trim();
            in_realms = section.eq_ignore_ascii_case("realms");
            in_realm_block = false;
            continue;
        }

        if in_realms && !in_realm_block {
            if line.to_uppercase().starts_with(&format!("{} =", realm_upper)) {
                in_realm_block = true;
                continue;
            }
        }

        if in_realm_block {
            let line_no_comment = line.split('#').next().unwrap_or("").trim();
            if let Some(eq_pos) = line_no_comment.find('=') {
                let key = line_no_comment[..eq_pos].trim().to_lowercase();
                let val = line_no_comment[eq_pos + 1..]
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'');
                if key == "kdc" {
                    return dns_resolve(val);
                }
            }
            if line.trim() == "}" {
                in_realm_block = false;
            }
        }
    }

    Err(format!(
        "在 {} 中未找到 {} 的 KDC 配置",
        path, realm
    ))
}

/// DNS 解析主机名到 IpAddr
fn dns_resolve(hostname: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return Ok(ip);
    }
    let addr_str = format!("{}:88", hostname);
    let mut addrs = addr_str
        .to_socket_addrs()
        .map_err(|e| format!("DNS 解析 {} 失败: {}", hostname, e))?;
    match addrs.next() {
        Some(sockaddr) => Ok(sockaddr.ip()),
        None => Err(format!("DNS 解析 {} 无结果", hostname)),
    }
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_principal() {
        assert_eq!(
            parse_principal("hdfs@XXX.COM"),
            Ok(("hdfs".to_string(), "XXX.COM".to_string()))
        );
        assert_eq!(
            parse_principal("hdfs/datanode1@XXX.COM"),
            Ok(("hdfs/datanode1".to_string(), "XXX.COM".to_string()))
        );
        assert!(parse_principal("invalid").is_err());
    }
}
