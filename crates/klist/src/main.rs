//! klist -- list Kerberos credential cache entries
//!
//! Usage:
//!   klist
//!   klist -e          (show etype detail)
//!   klist -c <path>   (specify ccache path)
//!   KRB5CCNAME=<path> klist

use chrono::{DateTime, TimeZone, Utc};
use kerberos_ccache::{CCache, CountedOctetString, Credential};
use kerberos_constants::etypes;
use std::env;
use std::fs;
use std::path::Path;

/// Resolve the ccache path.
/// Order: -c flag > KRB5CCNAME env > default ~/.qclaw/workspace/krb5cc_<USER>
fn resolve_ccache_path(args: &[String]) -> Result<String, String> {
    // Check -c flag
    let mut iter = args.iter().enumerate();
    while let Some((_, arg)) = iter.next() {
        if arg == "-c" {
            if let Some(path) = iter.next().map(|(_, p)| p) {
                return Ok(path.clone());
            } else {
                return Err("-c requires a path argument".to_string());
            }
        }
    }

    // Check KRB5CCNAME env (strip FILE: or WRFILE: prefix)
    if let Ok(val) = env::var("KRB5CCNAME") {
        let path = val
            .trim_start_matches("FILE:")
            .trim_start_matches("WRFILE:")
            .trim();
        if !path.is_empty() {
            return Ok(path.to_string());
        }
    }

    // Default: %TEMP%\krb5cc_<USERNAME>  (与 MIT kinit Windows 版行为一致)
    let user = env::var("USERNAME")
        .or_else(|_| env::var("USER"))
        .unwrap_or_else(|_| "unknown".to_string());
    let default = format!(
        "{}\\krb5cc_{}",
        env::var("TEMP")
            .or_else(|_| env::var("TMP"))
            .unwrap_or_else(|_| env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string())),
        user
    );
    if Path::new(&default).exists() {
        Ok(default)
    } else {
        Err("No credential cache found. Set KRB5CCNAME or run kinit first.".to_string())
    }
}

fn fmt_time(ts: u32) -> String {
    if ts == 0 {
        return "--".to_string();
    }
    Utc.timestamp_opt(ts as i64, 0)
        .single()
        .map(|dt: DateTime<Utc>| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| format!("<invalid: {}>", ts))
}

/// Format etype number to human-readable string.
/// keytype is used as fallback when etype == 0 (bug in older KeyBlock::new()).
fn fmt_etype(etype: u16, keytype_fallback: u16) -> String {
    let e = if etype != 0 { etype as i32 } else { keytype_fallback as i32 };
    match e {
        etypes::AES256_CTS_HMAC_SHA1_96 => "aes256-cts-hmac-sha1-96".to_string(),
        etypes::AES128_CTS_HMAC_SHA1_96 => "aes128-cts-hmac-sha1-96".to_string(),
        etypes::DES_CBC_CRC => "des-cbc-crc".to_string(),
        etypes::DES_CBC_MD5 => "des-cbc-md5".to_string(),
        etypes::RC4_HMAC => "arcfour-hmac".to_string(),
        etypes::RC4_HMAC_EXP => "arcfour-hmac-exp".to_string(),
        etypes::NO_ENCRYPTION => "null".to_string(),
        _ => format!("etype({})", e),
    }
}

/// Format principal: components/realm@realm
fn fmt_principal(realm: &CountedOctetString, components: &[CountedOctetString]) -> String {
    let realm_str = String::from_utf8_lossy(&realm.data);
    if components.is_empty() {
        realm_str.to_string()
    } else {
        let parts: Vec<String> = components
            .iter()
            .map(|c| String::from_utf8_lossy(&c.data).to_string())
            .collect();
        format!("{}@{}", parts.join("/"), realm_str)
    }
}

fn fmt_flags(flags: u32) -> String {
    let mut parts = Vec::new();
    // Kerberos ticket flags (RFC 4120, Section 5.3.1)
    if flags & 0x40000000 != 0 { parts.push("Forwardable"); }
    if flags & 0x20000000 != 0 { parts.push("Forwarded"); }
    if flags & 0x10000000 != 0 { parts.push("Proxiable"); }
    if flags & 0x08000000 != 0 { parts.push("Proxy"); }
    if flags & 0x04000000 != 0 { parts.push("May-postdate"); }
    if flags & 0x02000000 != 0 { parts.push("Postdated"); }
    if flags & 0x01000000 != 0 { parts.push("Invalid"); }
    if flags & 0x00800000 != 0 { parts.push("Renewable"); }
    if flags & 0x00400000 != 0 { parts.push("Initial"); }
    if flags & 0x00200000 != 0 { parts.push("Pre-authent"); }
    if flags & 0x00100000 != 0 { parts.push("HW-Authent"); }
    if flags & 0x00080000 != 0 { parts.push("Transited-policy-checked"); }
    if flags & 0x00040000 != 0 { parts.push("OK-As-Delegate"); }
    if flags & 0x00020000 != 0 { parts.push("Anonymous"); }
    if flags & 0x00010000 != 0 { parts.push("Name-canonicalize"); }
    if parts.is_empty() {
        format!("0x{:08x}", flags)
    } else {
        parts.join(", ")
    }
}

fn print_cred(cred: &Credential, idx: usize, show_etype_detail: bool) {
    let client = fmt_principal(&cred.client.realm, &cred.client.components);
    let server = fmt_principal(&cred.server.realm, &cred.server.components);

    println!();
    println!("{:2}. {}", idx, client);
    println!("    {}", server);

    if show_etype_detail {
        println!(
            "    EType:  {}  (keytype={}, etype={})",
            fmt_etype(cred.key.etype, cred.key.keytype),
            cred.key.keytype,
            cred.key.etype,
        );
    } else {
        println!("    EType: {}", fmt_etype(cred.key.etype, cred.key.keytype));
    }

    println!("    Flags: {}", fmt_flags(cred.tktflags));
    println!("    Auth Time:     {}", fmt_time(cred.time.authtime));
    println!("    Valid Starting:{}", fmt_time(cred.time.starttime));
    println!("    Expires:       {}", fmt_time(cred.time.endtime));
    println!("    Renew Till:    {}", fmt_time(cred.time.renew_till));
}

fn print_header(ccache: &CCache, path: &str) {
    let principal = fmt_principal(
        &ccache.primary_principal.realm,
        &ccache.primary_principal.components,
    );
    println!("Ticket cache: FILE:{}", path);
    println!("Default principal: {}", principal);
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let show_etype_detail = args.iter().any(|a| a == "-e" || a == "--etype");

    let ccache_path = resolve_ccache_path(&args)?;

    let data = fs::read(&ccache_path)
        .map_err(|e| format!("Failed to read ccache '{}': {}", ccache_path, e))?;

    let ccache = CCache::parse(&data)
        .map_err(|e| format!("Failed to parse ccache: {:?}", e))?
        .1;

    print_header(&ccache, &ccache_path);

    if ccache.credentials.is_empty() {
        println!("(no credentials)");
        return Ok(());
    }

    for (i, cred) in ccache.credentials.iter().enumerate() {
        print_cred(cred, i + 1, show_etype_detail);
        if i + 1 < ccache.credentials.len() {
            println!();
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("klist: {}", e);
        std::process::exit(1);
    }
}
