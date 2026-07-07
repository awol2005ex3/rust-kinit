# AGENTS.md - rust-kinit 开发规范与辅助文档

> 本文档供 AI Agent 在参与 rust-kinit 项目开发时参考。
> 包含项目结构、关键决策、编码规范、测试指南等。

---

## 项目概述

Rust 实现的 Kerberos `kinit` / `klist` 命令行工具，用于通过 keytab 文件获取 TGT 并管理 Kerberos 凭据缓存（ccache）。

**当前状态**：功能基本完成，kinit + klist 均可用，已修复上游 bug，Rust 2024 edition 兼容。所有 crate 已发布到 [crates.io](https://crates.io)（`awol2005ex3-*` 前缀）。新增 TGS 服务票据请求、AP-REQ 构建、GSS-API 消息保护引擎及全链路认证集成模块。

---

## 开发环境要求

- **Rust**: 1.85+（edition 2024 支持）
- **Cargo**: 随 Rust 安装
- **Windows**: MIT Kerberos for Windows（可选，用于对比测试）
- **参考 Skill**: `rust-dev-standards`（已安装在 `~/.qclaw/skills/rust-dev-standards/`）

---

## 项目结构详解

```
rust-kinit/
├── Cargo.toml                 # Workspace 配置（含 [workspace.package] 统一配置）
├── README.md                  # 用户文档（用法、构建、示例）
├── AGENTS.md                  # 本文件（开发规范）
├── LICENSE                    # AGPL-3.0
├── publish.ps1               # crates.io 发布脚本（自动跳过已发布版本）
├── crates/
│   ├── kinit-kt/             # kinit 命令行工具（crates.io: awol2005ex3-kinit-kt）
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs       # CLI 入口，调用 kinit_kt::request_tgt()
│   │       └── lib.rs        # 库接口
│   ├── klist/                # klist 命令行工具（crates.io: awol2005ex3-klist）
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── main.rs       # CLI 入口，读取并格式化 ccache
│   ├── kerbeiros/            # Kerberos AS-REQ/AS-REP/TGS 实现（awol2005ex3-kerbeiros）
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── as_requester.rs        # AS-REQ 请求器
│   │       ├── tgt_requester.rs       # TGT 请求器包装
│   │       ├── tgs_requester.rs       # [新增] TGS 服务票据请求器
│   │       ├── integration.rs         # [新增] KerberosAuthenticator 全链路认证
│   │       ├── gss_engine.rs          # [新增] GSS-API 消息保护引擎（JDK V2）
│   │       ├── utils.rs               # [新增] 工具函数（get_local_ip、resolve_realm_kdc）
│   │       ├── transporter.rs         # KDC 网络通信
│   │       ├── error.rs               # 错误类型
│   │       ├── mappers/               # 内部映射器
│   │       ├── messages/
│   │       │   ├── mod.rs
│   │       │   ├── asreq/             # AS-REQ 消息构建
│   │       │   └── ap_req.rs          # [新增] AP-REQ 消息构建器
│   │       └── credentials/
│   │           └── mappers/
│   │               └── credential_krb_info.rs  # [已修复] etype bug + 微软 KDC tag 兼容
│   ├── kerberos-asn1/       # Kerberos ASN.1 类型定义（awol2005ex3-kerberos-asn1）
│   ├── kerberos-ccache/     # ccache 文件格式读写（awol2005ex3-kerberos-ccache）
│   │   └── src/
│   │       ├── key_block.rs  # [已修复] KeyBlock::new() etype 硬编码 bug
│   │       └── credential.rs
│   ├── kerberos-constants/  # Kerberos 常量定义（awol2005ex3-kerberos-constants）
│   │   └── src/
│   │       └── ap_options.rs # [新增] AP-REQ 选项常量（MUTUAL_REQUIRED, USE_SESSION_KEY）
│   ├── kerberos-crypto/     # Kerberos 加密算法（awol2005ex3-kerberos-crypto）
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── checksum.rs   # [新增] checksum 函数（hmac-md5, sha-aes, sha-aes-le）
│   │       └── ...
│   ├── kerberos-keytab/    # keytab 文件格式解析（awol2005ex3-kerberos-keytab）
│   ├── mit-krb5-ccache/    # MIT krb5 FCC v4 ccache 写入（awol2005ex3-mit-krb5-ccache）
│   ├── red-asn1/            # ASN.1 DER 编码/解码库（awol2005ex3-red-asn1）
│   └── red-asn1-derive/     # ASN.1 derive 宏（awol2005ex3-red-asn1-derive）
```

---

## 代码地图（Code Map）

> 按 crate 列出每个模块的公共 API 签名。修改代码前先查此处，避免从头读完整代码。
> 标注格式：`pub fn 函数名(参数) -> 返回值` / `pub struct 结构体` / `pub enum 枚举`

---

### kerbeiros（核心认证库）

**crates/kerbeiros/src/lib.rs** — 根模块，pub use 重导出

| 导出路径 | 类目 |
|---|---|
| `Error`, `Result<T>` | enum / type alias (来自 `error.rs`) |
| `AsRequester`, `AsReqResponse`, `TgtRequester`, `TgsRequester`, `TgsReqResponse` | requesters 模块 |
| `TransportProtocol` | 传输协议枚举 |
| `Credential`, `CredentialWarehouse` | credentials 模块 |
| `GssChecksumData`, `ApReqOptions`, `ApReqBuilder` | messages/ap_req 模块 |
| `AsRep`, `AsReq`, `KrbError`, `TgsRep`, `TgsReq`, `EncTgsRepPart` | messages/mod (re-export from kerberos-asn1) |
| `KerberosAuthenticator`, `KerberosAuthOptions` | integration 模块 |
| `KerberosGssEngine` | gss_engine 模块 |
| `get_local_ip()`, `resolve_realm_kdc()` | utils 模块 |

---

#### error.rs — 错误类型

```rust
pub enum Error {
    Asn1Error(kerberos_asn1::Error),
    CryptographyError(kerberos_crypto::Error),
    InvalidAscii, InvalidUtf8, InvalidMicroseconds(u32),
    IOError, InvalidKeyCharset, InvalidKeyLength(usize),
    KrbErrorResponse(KrbError), NameResolutionError(String),
    NetworkError, NoKeyProvided, NoProvidedSupportedCipherAlgorithm,
    NotAvailableData(String), ParseAsRepError(AsRep, Box<Error>),
    PrincipalNameTypeUndefined(String), NoPrincipalName,
    NoAddress, BinaryParseError,
}
// Trait impls: From<kerberos_crypto::Error>, From<AsciiError>, From<Utf8Error>,
//              From<kerberos_asn1::Error>, From<kerberos_ccache::Error>
```

---

#### requesters/as_requester.rs — AS-REQ 请求器（最底层）

```rust
pub enum AsReqResponse { KrbError(KrbError), AsRep(AsRep) }

pub struct AsRequester;   // 私有字段
impl AsRequester {
    pub fn new(realm: AsciiString, kdc_address: IpAddr) -> Self;
    pub fn request(&self, username: &AsciiString, user_key: Option<&Key>) -> Result<AsReqResponse>;
    pub fn etypes(&self) -> &HashSet<i32>;
    pub fn set_etype(&mut self, etype: i32) -> Result<()>;
    pub fn set_etypes(&mut self, etypes: HashSet<i32>) -> Result<()>;
    pub fn kdc_options(&self) -> u32;
    pub fn realm(&self) -> &AsciiString;
    pub fn set_transport_protocol(&mut self, transport_protocol: TransportProtocol);
}
```

**内部流程**：`AsRequester::request()` → `AsRequest::request()` → 构建 AS-REQ → 发送到 KDC → 解析响应。

---

#### requesters/tgt_requester.rs — TGT 请求器（高层包装）

```rust
pub struct TgtRequester;   // 包裹 AsRequester
impl TgtRequester {
    pub fn new(realm: AsciiString, kdc_address: IpAddr) -> Self;
    pub fn request(&self, username: &AsciiString, user_key: Option<&Key>) -> Result<Credential>;
    pub fn etypes(&self) -> &HashSet<i32>;
    pub fn set_etype(&mut self, etype: i32) -> Result<()>;
    pub fn set_etypes(&mut self, etypes: HashSet<i32>) -> Result<()>;
    pub fn kdc_options(&self) -> u32;
    pub fn realm(&self) -> &AsciiString;
    pub fn set_transport_protocol(&mut self, transport_protocol: TransportProtocol);
}
```

**内部流程**（`TGTRequest::request()`）：
1. 发送 AS-REQ → 若返回 KrbError（PREAUTH_REQUIRED），解析 e-data 获取 salt
2. 获取 salt 后用密码构造加密时间戳 → 发送第二次 AS-REQ
3. 从 AS-REP 中提取 Credential

---

#### requesters/tgs_requester.rs — TGS 服务票据请求器

```rust
pub enum TgsReqResponse { KrbError(KrbError), TgsRep(TgsRep) }

pub struct TgsRequester;
impl TgsRequester {
    pub fn new(realm: AsciiString, kdc_address: IpAddr) -> Self;
    pub fn set_transport_protocol(&mut self, transport_protocol: TransportProtocol);
    /// 请求服务票据并返回 (Credential, 原始 TGS-REQ 字节)
    pub fn request_with_raw(&self, tgt_credential: &Credential, service_principal: &AsciiString) -> Result<(Credential, Vec<u8>)>;
    /// 请求服务票据，仅返回 Credential
    pub fn request(&self, tgt_credential: &Credential, service_principal: &AsciiString) -> Result<Credential>;
}
```

**内部流程**：
1. `build_tgs_req()` → 解析 SPN（"/" 分割组件，"@" 剔除 realm）→ 构造 KDC-REQ-BODY（含 local address）→ `build_ap_req_for_tgs()` 构建 AP-REQ 作为 PA-TGS-REQ → 添加 PA-PAC-REQUEST → 发送 TGS-REQ
2. `send_tgs_req()` → 发送到 KDC → `parse_tgs_response()` 解析 TGS-REP
3. `extract_credential_from_tgs_rep()` → 用 TGT session key 解密 TGS-REP 的 enc-part → 构造服务票据 Credential

**⚠ 注意**：`local_ip` 目前硬编码为 `10.110.149.18`，应改用 `utils::get_local_ip()`。

---

#### messages/ap_req.rs — AP-REQ 构建器

```rust
/// GSS checksum 提取数据
pub struct GssChecksumData {
    pub gss_initial_seq: u32,
    pub subkey: Vec<u8>,
    pub subkey_type: i32,
}

#[derive(Debug, Clone)]
pub struct ApReqOptions {
    pub mutual_required: bool,     // 默认 true
    pub use_session_key: bool,     // 默认 false
    pub gssapi_checksum: bool,     // 默认 true（兼容 Java JGSS）
    pub time_offset_secs: i64,     // 默认 0（时钟偏移修正，正=客户端慢）
}

pub struct ApReqBuilder<'a>;       // 持有 &Credential
impl ApReqBuilder<'a> {
    pub fn new(credential: &'a Credential) -> Self;
    pub fn with_options(mut self, options: ApReqOptions) -> Self;
    /// 返回 DER 编码的 AP-REQ bytes
    pub fn build(&self) -> Result<Vec<u8>>;
    /// 返回 (AP-REQ bytes, GssChecksumData)
    pub fn build_with_gss_data(&self) -> Result<(Vec<u8>, GssChecksumData)>;
}
```

**内部流程**（`build_impl()`）：
1. 生成随机 subkey（AES key）和初始序列号
2. 构建 GSSAPI checksum（cksumtype=0x8003, GSS_C_AF_EXT 格式）
3. 构建 Authenticator（含 subkey + seq_number）
4. 用服务 ticket 的 session key 加密 Authenticator
5. 组装 AP-REQ（ApReq { pvno, msg_type, ap_options, ticket, authenticator }）
6. DER 编码输出

---

#### gss_engine.rs — GSS-API 消息保护引擎

```rust
pub struct KerberosGssEngine;  // 私有字段: session_key, aes_sizes, seq_num
impl KerberosGssEngine {
    pub fn new(session_key: Vec<u8>, key_type: i32) -> Self;
    pub fn new_with_seq(session_key: Vec<u8>, key_type: i32, seq_num: u32) -> Self;
    /// 指定 key_usage 的 WRAP（用于 accept 端，_ku_java 无特殊含义）
    pub fn wrap_with_ku_java(&mut self, plaintext: &[u8], key_usage: i32) -> io::Result<Vec<u8>>;
    /// 默认 initiator WRAP（key_usage=24），自动递增 seq_num
    pub fn wrap(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>>;
    /// 尝试 4 种 key_usage 解 WRAP/MIC token
    pub fn unwrap(&mut self, token: &[u8]) -> io::Result<Vec<u8>>;
    pub fn seq_num(&self) -> u32;
    pub fn reset_seq_num(&mut self, seq: u32);
}
```

**WRAP 令牌格式**（JDK V2, non-confidential）：
```
[16B header][payload][12B checksum]
  header: TOK_ID(2) + Flags(1) + FILLER(1) + EC(2) + RRC(2) + SND_SEQ(8)
  TOK_ID: 0x0504=WRAP, 0x0404=MIC
```

**关键逻辑**：
- checksum = `checksum_sha_aes(key, key_usage, header_cleared + data, &aes_sizes)`
- unwrap 顺序：key_usage 24（init_seal）→ 22（accep_seal）→ 25（init_sign）→ 23（accep_sign）

---

#### integration.rs — 全链路认证

```rust
#[derive(Debug, Clone)]
pub struct KerberosAuthOptions {
    pub realm: AsciiString,
    pub kdc_address: IpAddr,
    pub kdc_port: Option<u16>,           // 默认 Some(88)
    pub username: AsciiString,
    pub user_key: Key,
    pub service_principal: AsciiString,
    pub mutual_required: bool,           // 默认 true
    pub time_offset_secs: i64,           // 默认 0
}

pub struct KerberosAuthenticator;   // 私有字段: options
impl KerberosAuthenticator {
    pub fn new(options: KerberosAuthOptions) -> Self;
    /// 一站式认证：TGT → TGS → AP-REQ，返回 AP-REQ bytes
    pub fn authenticate(&self) -> crate::Result<Vec<u8>>;
    /// 返回 (AP-REQ bytes, 服务票证 Credential)
    pub fn authenticate_full(&self) -> crate::Result<(Vec<u8>, Credential)>;
    /// 返回 (AP-REQ bytes, Credential, GSS 初始序列号)
    pub fn authenticate_full_with_seq(&self) -> crate::Result<(Vec<u8>, Credential, u32)>;
    /// 返回 (AP-REQ bytes, Credential, GSS init seq, subkey_type, subkey, gss_flags)
    /// subkey 和 subkey_type 用于初始化 KerberosGssEngine
    pub fn authenticate_full_with_seq_and_subkey(&self)
        -> crate::Result<(Vec<u8>, Credential, u32, u32, Vec<u8>, i32)>;
}
```

**调用链**：`authenticate()` → `TgtRequester::request()` → `TgsRequester::request()` → `ApReqBuilder::build_with_gss_data()`

---

#### utils.rs — 工具函数

```rust
/// 获取本机非 loopback IPv4 地址
pub fn get_local_ip() -> Option<IpAddr>;
/// 通过 DNS SRV 查询 _kerberos._tcp.<REALM> 获取 KDC 地址
pub fn resolve_realm_kdc(realm: &AsciiString) -> Result<IpAddr>;
```

#### credentials/credential.rs — 凭据数据结构

```rust
pub struct Credential;  // 私有字段: crealm, cname, ticket, client_part(EncAsRepPart)
impl Credential {
    pub fn new(crealm: Realm, cname: PrincipalName, ticket: Ticket, client_part: EncAsRepPart) -> Self;
    pub fn crealm(&self) -> &Realm;
    pub fn cname(&self) -> &PrincipalName;
    pub fn ticket(&self) -> &Ticket;
    pub fn authtime(&self) -> &KerberosTime;
    pub fn starttime(&self) -> Option<&KerberosTime>;
    pub fn endtime(&self) -> &KerberosTime;
    pub fn renew_till(&self) -> Option<&KerberosTime>;
    pub fn flags(&self) -> &TicketFlags;
    pub fn key(&self) -> &EncryptionKey;       // ← session key（解密/加密用）
    pub fn srealm(&self) -> &KerberosString;
    pub fn sname(&self) -> &PrincipalName;
    pub fn caddr(&self) -> Option<&HostAddresses>;
    pub fn encrypted_pa_data(&self) -> Option<&MethodData>;
    pub fn save_into_ccache_file(self, path: &str) -> Result<()>;
    pub fn save_into_krb_cred_file(self, path: &str) -> Result<()>;
}
// Trait impls: TryFrom<kerberos_ccache::Credential>, From<Credential> for kerberos_ccache::Credential
```

#### credentials/credential_warehouse.rs — 凭据仓库

```rust
pub struct CredentialWarehouse {
    pub credentials: Vec<Credential>,
    pub realm: Realm,
    pub client: PrincipalName,
}
impl CredentialWarehouse {
    pub fn new(realm: Realm, client: PrincipalName, credentials: Vec<Credential>) -> Self;
    pub fn save_into_ccache_file(&self, path: &str) -> error::Result<()>;
    pub fn save_into_krb_cred_file(&self, path: &str) -> error::Result<()>;
}
// Trait impls: From<Credential>, TryFrom<CCache>, From<CredentialWarehouse> for CCache
```

---

### kerberos-crypto（加密算法库）

**crates/kerberos-crypto/src/lib.rs** — 核心加密逻辑

```rust
// 枚举
pub enum Key { Secret(String), RC4Key([u8;16]), AES128Key([u8;16]), AES256Key([u8;32]) }
pub enum AesSizes { Aes128, Aes256 }

// Trait
pub trait KerberosCipher {
    fn encrypt(&self, key: &[u8], key_usage: i32, plaintext: &[u8]) -> Vec<u8>;
    fn decrypt(&self, key: &[u8], key_usage: i32, ciphertext: &[u8]) -> Result<Vec<u8>>;
    fn generate_key_from_string_and_encrypt(&self, password: &str, salt: &[u8], ku: i32, pt: &[u8]) -> Vec<u8>;
    fn generate_key_from_string_and_decrypt(&self, password: &str, salt: &[u8], ku: i32, ct: &[u8]) -> Result<Vec<u8>>;
}

// 工厂函数
pub fn new_kerberos_cipher(etype: i32) -> Result<Box<dyn KerberosCipher>>;
// 支持的 etype: 18(AES256), 17(AES128), 23(RC4)

// Checksum 函数（关键！GSS 引擎和 TGS 都调用）
pub fn checksum_hmac_md5(key: &[u8], key_usage: i32, plaintext: &[u8]) -> Vec<u8>;
pub fn checksum_sha_aes(key: &[u8], key_usage: i32, plaintext: &[u8], aes_sizes: &AesSizes) -> Vec<u8>;
pub fn checksum_sha_aes_le(key: &[u8], key_usage: i32, plaintext: &[u8], aes_sizes: &AesSizes) -> Vec<u8>;
//                   ^^ 注意: checksum_sha_aes_le 使用小端 key_usage，用于 Java JGSS 兼容

// DK (derive key) 函数 — 内部使用
pub fn dk(key: &[u8], key_usage: i32, aes_sizes: &AesSizes) -> Vec<u8>;

// 辅助
pub fn is_supported_etype(etype: i32) -> bool;
pub fn supported_etypes() -> HashSet<i32>;
```

---

### kerberos-constants（常量定义）

**crates/kerberos-constants/src/**
所有模块均为 `pub mod xxx`，只导出常量，无函数/类型：

| 模块 | 关键常量 |
|---|---|
| `etypes` | `AES256_CTS_HMAC_SHA1_96=18`, `AES128_CTS_HMAC_SHA1_96=17`, `RC4_HMAC=23` |
| `key_usages` | `KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP=1`, `KEY_USAGE_AP_REQ_AUTHEN=11`, `KEY_USAGE_TGS_REQ_PA_TGS_REQ=7`, 等 |
| `ap_options` | `RESERVED=0x80000000`, `USE_SESSION_KEY=0x40000000`, `MUTUAL_REQUIRED=0x20000000` |
| `ticket_flags` | `FORWARDABLE=0x40000000`, `RENEWABLE=0x04000000`, `INITIAL=0x00400000` 等 |
| `kdc_options` | `FORWARDABLE=0x40000000`, `RENEWABLE_OK=0x00000010` 等 |
| `pa_data_types` | `PA_TGS_REQ=1`, `PA_PAC_REQUEST=128` |
| `principal_names` | `NT_PRINCIPAL=1`, `NT_SRV_INST=2` |
| `error_codes` | `KDC_ERR_PREAUTH_REQUIRED=25` |
| `checksum_types` | `HMAC_SHA1_96_AES_8003=0x8003` |

---

### kerberos-ccache（ccache 文件读/写，基于 nom）

**crates/kerberos-ccache/src/lib.rs** — nom 解析器实现

```rust
// 核心数据结构
pub struct CountedOctetString(pub Vec<u8>);   // 带 4B 长度前缀的字节串
pub struct Principal { pub name_type: u32, pub realm: CountedOctetString, pub components: Vec<CountedOctetString> }
pub struct KeyBlock { pub keytype: u16, pub etype: u16, pub keyvalue: Vec<u8> }
pub struct Times { pub authtime: u32, pub starttime: u32, pub endtime: u32, pub renew_till: u32 }
pub struct Address { pub addr_type: u16, pub addr_data: CountedOctetString }
pub struct AuthData { pub ad_type: u16, pub ad_data: CountedOctetString }
pub struct Credential { pub client, server, key, time, is_skey, tktflags, addrs, authdata, ticket, second_ticket }
pub struct CCache { pub header: Header, pub primary_principal: Principal, pub credentials: Vec<Credential> }

// 关键方法
impl KeyBlock {
    pub fn new(keytype: u16, keyvalue: Vec<u8>) -> Self;   // etype = keytype ← ADR-002 修复
    pub fn new_with_etype(keytype: u16, etype: u16, keyvalue: Vec<u8>) -> Self;
    pub fn build(&self) -> Vec<u8>;
    pub fn parse(raw: &[u8]) -> IResult<&[u8], Self>;       // nom 解析器
}
```

**注意**：此 crate 使用 `nom 7`，需要 `nom::Err` 和 `nom::IResult`。

---

### kerberos-keytab（keytab 文件解析）

**crates/kerberos-keytab/src/lib.rs** — 支持 MIT keytab 格式

```rust
pub use counted_octet_string::CountedOctetString;
pub use key_block::KeyBlock;
pub use keytab_entry::KeytabEntry;
pub use keytab::Keytab;
```

内部结构类似 ccache。

---

### mit-krb5-ccache（MIT krb5 FCC v4 写入）

**crates/mit-krb5-ccache/src/lib.rs** — MIT 兼容的 ccache 序列化

```rust
pub struct Principal { pub name_type: u32, pub realm: String, pub components: Vec<String> }
pub struct KeyBlock { pub enctype: u16, pub keyvalue: Vec<u8> }
pub struct Times { pub authtime, starttime, endtime, renew_till: u32 }
pub struct HostAddr { pub addr_type: u16, pub addr_data: Vec<u8> }
pub struct AuthData { pub ad_type: u16, pub ad_data: Vec<u8> }
pub struct Credential { pub client, server, key, time, is_skey, tktflags, addrs, authdata, ticket, second_ticket }
pub struct CCache { pub default_principal: Principal, pub credentials: Vec<Credential> }

impl CCache {
    pub fn new(default_principal: Principal, credentials: Vec<Credential>) -> Self;
    pub fn build(&self) -> Vec<u8>;           // 序列化为字节
    pub fn parse(data: &[u8]) -> io::Result<(usize, Self)>;
    pub fn write_to_file(&self, path: &str) -> io::Result<()>;
    pub fn read_from_file(path: &str) -> io::Result<Self>;
}
```

所有子结构均有 `build()` / `parse()` 方法。

---

### kinit-kt（命令行工具库）

**crates/kinit-kt/src/lib.rs**

```rust
/// keytab → TGT 获取 → 写入 ccache 文件
/// krb5_ini_path: 可选 krb5.ini 配置文件路径（用于 KDC 解析）
pub fn request_tgt(keytab_path: &str, principal: &str, krb5_ini_path: Option<&str>) -> Result<Vec<u8>, String>;

/// 返回 Credential 而非写入文件（编程接口）
pub fn request_tgt_credential(keytab_path: &str, principal: &str, krb5_ini_path: Option<&str>)
    -> Result<kerbeiros::credentials::Credential, String>;
```

**内部流程**（`request_tgt`）：
1. `parse_principal(principal)` → 拆分 `user@REALM`
2. 加载 keytab → `find_key_in_keytab()` → 匹配 principal_name + realm
3. `resolve_kdc(realm, krb5_ini_path)` → 读取 krb5.ini / DNS SRV / 默认域名解析
4. `TgtRequester::new(realm, kdc_address).request(&username, &key)` → `build_mit_ccache()` → 写入文件

---

### klist（ccache 查看工具）

**crates/klist/src/main.rs** — 二进制入口

```
命令行参数：
  klist                          → 显示默认 ccache
  klist -c <path>                → 指定路径
  klist -e                       → 显示 etype/keytype 详情
  环境变量 KRB5CCNAME            → 覆盖默认路径（支持 FILE: 前缀）
```

内部函数（全部为私有）：
- `resolve_ccache_path(args) -> Result<String, String>`
- `fmt_time(ts: u32) -> String`
- `fmt_etype(etype: u16, keytype_fallback: u16) -> String`
- `fmt_principal(realm, components) -> String`
- `fmt_flags(flags: u32) -> String`
- `print_cred(cred, idx, show_etype_detail)`
- `print_header(ccache, path)`
- `run() -> Result<(), String>`

---

### 跨 crate 调用链速查

```
kinit-kt:
  request_tgt() / request_tgt_credential()
    → keytab 解析 (kerberos-keytab)
    → TgtRequester::request() (kerbeiros)
      → AsRequester::request()
        → ASN.1 编码/解码 (kerberos-asn1 + red-asn1)
        → 网络传输 (kerbeiros::transporter)
        → 加密/解密 (kerberos-crypto)
    → mit-krb5-ccache 写入 (mit-krb5-ccache)

klist:
  main() → mit-krb5-ccache::CCache::read_from_file() → 分行格式化输出

编程接口 - 全链路:
  KerberosAuthenticator::authenticate()
    → TgtRequester::request()          (as above)
    → TgsRequester::request()
      → build_tgs_req()
        → ApReqBuilder (for PA-TGS-REQ 内的 AP-REQ)
        → send_tgs_req() → KDC → parse TGS-REP
      → extract_credential_from_tgs_rep()
    → ApReqBuilder::build_with_gss_data()
      → 构建 Authenticator（含 GSSAPI checksum + subkey）
      → 用 session key 加密 → 输出 DER 编码 AP-REQ

GSS 消息保护:
  KerberosGssEngine::wrap(plaintext)
    → 构建 16B JDK V2 header
    → checksum_sha_aes(key, key_usage, header_cleared + data, &aes_sizes)
    → 输出 [header][data][checksum]

  KerberosGssEngine::unwrap(token)
    → 解析 header → 提取 key_usage(22..25) 循环尝试
    → checksum_sha_aes 校验 → 通过则返回 payload
```

---

## 关键设计决策记录（ADR）

### ADR-001: Fork himmelblau_* crates 并独立维护

**状态**: 已决定  
**背景**: 上游 `himmelblau_kerbeiros` 存在 bug（etype 使用错误、微软 KDC 不兼容），且无法直接贡献补丁。  
**决策**: Fork 所有 8 个 `himmelblau_*` crate，去掉 `himmelblau_` 前缀，移入 `crates/` 目录以 workspace path 依赖管理。  
**后果**:
- 项目完全自包含，无外部 crate 依赖（除 `chrono`, `cipher`, `nom` 等少量依赖）
- 可以自由修复上游 bug
- 发布到 crates.io 时使用 `awol2005ex3-` 前缀避免与原始 crate 冲突
- 需要手动跟进上游安全更新（目前无计划）

### ADR-002: 修复 KeyBlock::new() etype 硬编码为 0 的 bug

**状态**: 已修复  
**背景**: `KeyBlock::new(keytype, keyvalue)` 将 `etype` 字段硬编码为 0，导致 `klist` 显示 `EType: null`。  
**修复**: 修改 `kerberos-ccache/src/key_block.rs`，将 `etype: keytype`（使用与 keytype 相同的值）。  
**验证**: `klist` 现在正确显示 `EType: aes256-cts-hmac-sha1-96`。

### ADR-003: 修复 credential_krb_info.rs 中 etype 使用错误

**状态**: 已修复  
**背景**: `try_decrypt_enc_kdc_rep_part_with_cipher_key` 使用 `key.etypes()[0]` 而非 `kdc_rep.enc_part.etype`，导致解密失败（`ParseAsRepError: UnmatchedTag(Application)`）。  
**修复**: 改用 `kdc_rep.enc_part.etype` 作为解密的 etype。  
**文件**: `crates/kerbeiros/src/credentials/mappers/credential_krb_info.rs`

### ADR-004: 兼容微软 KDC APPLICATION tag 扩展

**状态**: 已修复  
**背景**: 微软 KDC 返回的 `EncAsRepPart` 使用 tag `0x7a`（`Application 26`）而非标准 `0x79`（`Application 25`），导致 ASN.1 解析失败。  
**修复**: 在 `credential_krb_info.rs` 的 `try_decrypt_enc_kdc_rep_part_with_cipher_key` 中添加 APPLICATION tag 修正：`0x7a` → `0x79`。  
**文件**: `crates/kerbeiros/src/credentials/mappers/credential_krb_info.rs`

### ADR-005: ccache 默认路径与 MIT kinit 对齐

**状态**: 已决定  
**背景**: 原实现使用当前目录或 `~/.qclaw/workspace/`，与 MIT kinit 行为不一致。  
**决策**: 默认路径改为 `%TEMP%\krb5cc_<USERNAME>`（Windows 用户名），与 MIT Kerberos for Windows 一致。  
**实现**:
- `kinit-kt`: 使用 `%USERNAME%`（Windows 用户名）作为文件名
- `klist`: 默认路径同样使用 `%TEMP%\krb5cc_<USERNAME>`
- 支持 `KRB5CCNAME` 环境变量（自动 strip `FILE:` / `WRFILE:` 前缀）

### ADR-006: klist 输出格式采用分行格式（非表格）

**状态**: 已决定  
**背景**: 初始实现使用固定宽度表格，在 Windows 终端中因 ANSI 转义序列导致错位。  
**决策**: 去掉表头分隔线，改用分行格式（各字段一行，固定缩进）。  
**优点**: 兼容所有终端，不依赖等宽字体或 ANSI 支持。

### ADR-007: Rust 2024 Edition 兼容

**状态**: 已完成  
**背景**: 项目使用 `edition = "2024"`，需要修复 Rust 2024 中移除或更改的语法。  
**修复项**:
1. 移除 `ref` 绑定模式（`kerberos-crypto/src/key.rs`, `red-asn1-derive/src/parser.rs`）
2. 转义保留关键字（`gen` → `r#gen` in `kerbeiros/src/messages/asreq/builder.rs`）
3. 修复 `chrono` 弃用方法（`Utc::ymd()` → `Utc.with_ymd_and_hms()`, `timestamp()` → `timestamp_opt()`）
4. 修复 `red-asn1-derive` 依赖（`syn 0.15` / `quote 0.6` / `proc-macro2 0.4` 锁定到旧版本）

### ADR-008: crates.io 发布及 workspace 统一配置

**状态**: 已完成  
**背景**: 需要将项目发布到 crates.io，原始包名在 crates.io 上已被占用。  
**决策**:  
- 所有 crate 名称添加 `awol2005ex3-` 前缀（如 `awol2005ex3-kerberos-constants`）
- 使用 `[workspace.package]` 统一配置 license（AGPL-3.0）、edition（2024）、repository
- path 依赖保留原 key 名称，通过 `package = "awol2005ex3-xxx"` 映射
- Rust 源码中 `use` 语句无需改动
- 新增 `publish.ps1` 脚本按依赖顺序逐个发布，自动跳过已有版本

### ADR-009: TGS 请求器实现——SPN 解析及 NT_PRINCIPAL

**状态**: 已实现  
**背景**: 需要从 TGT 凭证向 KDC 请求指定 SPN 的服务票据，用于后续 AP-REQ 构建。MIT krb5 的 `gss_accept_sec_context` 严格检查 ticket 中 sname 的 name_type 是否为 NT_PRINCIPAL。  
**决策**:  
- SPN 字符串按 `'/'` 分割组件，按 `'@'` 剔除 REALM 后缀
- sname name_type 固定使用 `NT_PRINCIPAL`（值=1）
- TGS-REQ 中包含本地 IP 地址（微软 KDC 要求含 address 字段才能下发 PAC）
- 发送 PA-PAC-REQUEST 以请求授权数据（PAC）  
**文件**: `crates/kerbeiros/src/requesters/tgs_requester.rs`

### ADR-010: AP-REQ 构建——GSSAPI checksum 与 subkey 策略

**状态**: 已实现  
**背景**: AP-REQ 是 Kerberos 认证的最后一步，需要包含服务票据和加密的 Authenticator。Java JGSS（OpenJDK）对 AP-REQ 格式有严格要求：
1. GSSAPI checksum 必须使用 cksumtype=0x8003，且第一个字节必须是 `0x10`（GSS_C_AF_EXT）
2. subkey 必须非空（MIT krb5 使用 subkey 作为 GSS per-message 的 base key）  
**决策**:  
- Authenticator 始终包含 subkey（随机 AES 密钥）和 seq_number
- GSSAPI checksum 格式按 RFC 4121 §4.1.1.1 + MIT krb5 make_checksum.c 实现
- GSS flags: mutual_required=true 时 0x0000000E，否则 0x0000000C  
**文件**: `crates/kerbeiros/src/messages/ap_req.rs`

### ADR-011: GSS 引擎——JDK V2 格式 WRAP/MIC 保护

**状态**: 已实现  
**背景**: Thrift SASL 认证后，需要 GSS-API 消息保护（wrap/unwrap）以保证数据传输完整性。JDK 的 GSS 实现使用自定义 V2 格式。  
**决策**:  
- 16 字节 MessageTokenHeader（TOK_ID + Flags + FILLER + EC + RRC + SND_SEQ）
- Checksum 使用 SHA-1 HMAC（12B），支持 4 种 key_usage（22/23/24/25）
- Unwrap 自动尝试所有 key_usage 以兼容不同 JDK 实现
- 支持 subkey 模式，兼容 Java JGSS useSubkey=true  
**文件**: `crates/kerbeiros/src/gss_engine.rs`

### ADR-012: KerberosAuthenticator 全链路认证集成

**状态**: 已实现  
**背景**: 需要提供一站式 API 封装 TGT → TGS → AP-REQ 整个流程，简化用户调用。  
**决策**:  
- `KerberosAuthenticator` 提供 4 种返回模式：
  - `authenticate()` → AP-REQ bytes（Thrift SASL 最简接口）
  - `authenticate_full()` → AP-REQ + Credential
  - `authenticate_full_with_seq()` → AP-REQ + Credential + GSS init seq
  - `authenticate_full_with_seq_and_subkey()` → 完整信息含 subkey（Java JGSS 兼容）
- `KerberosAuthOptions` 包含 realm、KDC 地址、端口、用户名、密钥、SPN、mutual auth、时间偏移等  
**文件**: `crates/kerbeiros/src/integration.rs`

### ADR-013: checksum 函数——小端 AES 校验支持

**状态**: 已实现  
**背景**: Java JGSS（OpenJDK）在 GSS 消息保护中使用 little-endian key_usage 编码进行 AES checksum 计算，与 RFC 3962 的 big-endian 标准不同。  
**决策**: 新增 `checksum_sha_aes_le()` 函数，使用 little-endian 编码的 key_usage 输入 `dk()`，与 Java 实现兼容。  
**文件**: `crates/kerberos-crypto/src/checksum.rs`

---

## 编码规范

遵循 `~/.qclaw/skills/rust-dev-standards/SKILL.md` 中的规范，重点包括：

1. **优先使用 Rust 标准库**：避免不必要的依赖
2. **错误处理**: 使用 `Result<T, Box<dyn Error>>` 或自定义错误类型
3. **测试**: 每个关键函数都有单元测试
4. **文档**: 公共 API 必须有 `///` 文档注释
5. **格式化**: 使用 `cargo fmt` 自动格式化
6. **Lint**: 使用 `cargo clippy` 检查代码质量

---

## 测试指南

### 单元测试

```bash
cargo test
cargo test -p kerberos-ccache
cargo test -p kerbeiros
cargo test -p kerberos-crypto          # checksum 单元测试
```

### 集成测试

```bash
# 使用 keytab 获取 TGT
cargo run --bin kinit -- -kt "D:\path\to\hdfs.keytab" hdfs@XXX.COM

# 列出 ccache 内容
cargo run --bin klist
cargo run --bin klist -c "D:\path\to\krb5cc_hdfs"
cargo run --bin klist -e
```

### GSS 引擎单元测试

```bash
cargo test -p kerbeiros gss_engine
cargo test -p kerbeiros ap_req
cargo test -p kerbeiros tgs_requester
cargo test -p kerberos-crypto checksum
```

### 对比测试（与 MIT kinit）

```bash
# MIT kinit
kinit.exe -kt hdfs.keytab hdfs@XXX.COM
klist.exe

# rust-kinit
cargo run --bin kinit -- -kt hdfs.keytab hdfs@XXX.COM
cargo run --bin klist
```

对比两者的 ccache 文件和输出格式是否一致。

---

## 后续开发注意事项

### 待实现功能

1. **kdestroy**: 清除 ccache 文件
2. **klist -v**: 详细模式（显示更多字段，如 `Addresses`, `Auth-Data`）
3. **支持更多加密类型**: 目前支持 AES256/128、RC4，可添加 DES/3DES（如需）
4. **支持 KEYRING ccache 类型**（Linux）
5. **交叉编译**: 支持 Linux/macOS 构建
6. **AP-REP 验证**: 支持 mutual authentication 的 AP-REP 响应解析
7. **GSS 加密 WRAP**: 当前 WRAP 仅做完整性校验，未实现加密负载（confidentiality）

### 已知问题

1. **错误信息用中文**: 部分错误信息是中文（kinit-kt, mit-krb5-ccache 等），如需国际化需重构
2. **TGS-REQ 本地 IP 硬编码**: `tgs_requester.rs` 中 local_ip 硬编码为 `10.110.149.18`，需改为动态获取（已有 `utils::get_local_ip()` 可用）

### 依赖更新

- **chrono**: 目前使用 `0.4`，如有安全更新需及时升级
- **cipher**: `kerberos-crypto` 依赖 `cipher` crate，API 可能有变化（已从 `decrypt_padded_vec_mut` 改为 `decrypt_padded_mut`）
- **nom**: `kerberos-ccache` 和 `kerberos-keytab` 使用 `nom 7`，`red-asn1` 使用 `nom 8`，目前共存无冲突

---

## 常见问题（FAQ）

### Q: 为什么 fork himmelblau_* crates 而不是提交上游 PR？

A: 上游 `himmelblau_kerbeiros` 是 `himmelblau` 项目（Azure AD 集成）的一部分，修复可能影响其他功能。且我们的修复（微软 KDC 兼容）可能不具备通用性。Fork 后可以自由控制代码质量，发布到 crates.io 时使用 `awol2005ex3-` 前缀避免命名冲突。

### Q: 为什么不用 `kerberos` crate（crates.io 上的）？

A: `kerberos` crate 不支持 keytab 文件，且 AS-REQ 实现不完整。我们选择 fork `himmelblau_kerbeiros` 并修复 bug。

### Q: 如何调试 AS-REQ/AS-REP 流程？

A: 在 `credential_krb_info.rs` 中添加 `eprintln!` 调试输出，或设置 `RUST_LOG=debug` 环境变量（需添加 `env_logger` 依赖）。

### Q: 为什么 klist 显示 `EType: null`？

A: 这是 `KeyBlock::new()` 的 bug，已将 `etype` 改为 `keytype`。如仍出现，检查 `KeyBlockMapper::encryption_key_to_keyblock` 是否正确设置 `etype`。

### Q: GSS checksum 验证失败怎么办？

A: `KerberosGssEngine::unwrap()` 会依次尝试 key_usage 22、24、23、25。如全部失败，检查：
1. session_key 是否匹配服务器端密钥
2. 初始序列号（init_seq）是否正确
3. 服务票据的 etype 是否与引擎的 key_type 一致

### Q: AP-REQ 被 Java 服务端拒绝（"Incorrect checksum"）？

A: 检查 GSSAPI checksum 的第一个字节是否为 `0x10`（GSS_C_AF_EXT）。OpenJDK 的 `OverloadedChecksum` 类要求 checksum 前 4 字节为 `[0x10, 0x00, 0x00, 0x00]`，否则抛出 "Incorrect checksum" 异常。

### Q: 服务票据缺少 PAC（authorization data）？

A: 微软 KDC 要求同时满足两个条件才会在服务票据中包含 PAC：
1. TGS-REQ 的 PA-DATA 中包含 PA-PAC-REQUEST（`KerbPaPacRequest::new(true)`）
2. TGS-REQ 的 KDC-REQ-BODY 中包含 `addresses` 字段（本地 IP）
如缺少 PAC，Hive 等服务会拒绝 GSS 上下文。

---

## GSS 引擎设计细节

`KerberosGssEngine` (JDK V2 格式)：

```
JDK MessageTokenHeader (16 bytes):
  [0-1]:   TOK_ID (0x0504=WRAP, 0x0404=MIC)
  [2]:     Flags (1=SENDER_IS_ACCEPTOR, 2=CONFIDENTIAL, 4=ACCEPTOR_SUBKEY)
  [3]:     FILLER = 0xff
  [4-5]:   EC (0x000c for non-confidential WRAP)
  [6-7]:   RRC (0)
  [8-15]:  SND_SEQ (64-bit big-endian)

Checksum CI:
  buf = [data(0..len)][header(16B)]
  header[4..7] cleared (EC + RRC set to 0)
  checksum_sha_aes(key, key_usage, buf, &aes_sizes)

key_usage:
  22 = acceptor_seal, 23 = acceptor_sign
  24 = initiator_seal, 25 = initiator_sign

Wire format (non-conf WRAP):
  [16B header][payload][12B checksum]
```

---

## 更新记录

- **2026-06-17**: 初始版本，记录项目结构、关键决策、编码规范
- **2026-06-25**: 
  - 所有 crate 包名添加 `awol2005ex3-` 前缀以发布 crates.io
  - 新增 `[workspace.package]` 统一配置（license, edition, repository）
  - 全部 crate 统一使用 edition 2024
  - mit-krb5-ccache 许可证从 MIT 改为 AGPL-3.0
  - 仓库地址设置为 `https://gitee.com/awol2010ex/rust-kinit`
  - 新增 publish.ps1 发布脚本
  - 清理已删除的旧目录/文件（src/, vendor/, klist.rs）的文档引用
- **2026-07-07**:
  - 新增 TGS 请求器实现（ADR-009），支持服务票据获取及 PAC 请求
  - 新增 AP-REQ 消息构建器（ADR-010），支持 GSSAPI checksum 和 subkey
  - 新增 GSS 引擎（ADR-011），JDK V2 格式 WRAP/MIC 消息保护
  - 新增 KerberosAuthenticator 全链路认证集成（ADR-012）
  - 新增 checksum 函数（ADR-013），支持 HMAC-MD5、SHA-AES、SHA-AES-LE
  - 新增 AP 选项常量（MUTUAL_REQUIRED, USE_SESSION_KEY）
  - 新增工具函数（get_local_ip, resolve_realm_kdc）
  - 重构 GSS 引擎适配 JDK V2 格式，移除调试日志
  - 清理冗余调试打印日志
  - 新增代码地图（Code Map）章节，按 crate 列出所有公共 API 签名、关键函数、内部流程及跨 crate 调用链

---

## 许可证

本项目采用 **AGPL-3.0**（GNU Affero General Public License v3.0）开源协议（包括 `mit-krb5-ccache`）。
