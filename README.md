# rust-kinit

Rust 实现的 Kerberos `kinit` / `klist` 命令行工具 + Kerberos 认证库，用于通过 keytab 文件获取 TGT（Ticket Granting Ticket）、请求服务票据（TGS）、构建 AP-REQ 消息，并提供 GSS-API 消息保护能力。

**源码仓库**: <https://gitee.com/awol2010ex/rust-kinit>

**发布包**: [crates.io](https://crates.io) 上以 `awol2005ex3-` 前缀发布（如 `awol2005ex3-kinit-kt`, `awol2005ex3-klist`, `awol2005ex3-kerbeiros` 等）

## 功能特性

### 命令行工具
- **kinit**：通过 keytab 文件获取 TGT，兼容 MIT kinit 行为
- **klist**：列出 ccache 中的 Kerberos 凭据信息

### 核心库（kerbeiros）
- **TGT 获取**：AS-REQ/AS-REP 协议，支持密码/keytab 认证
- **TGS 服务票据请求**：通过 TGT 向 KDC 请求指定 SPN 的服务票据
- **AP-REQ 构建**：构建 Kerberos AP-REQ 消息（支持 GSSAPI checksum、subkey、mutual auth）
- **GSS 消息保护**：JDK V2 格式 WRAP/MIC 令牌（SHA-1 checksum，适配 Java JGSS）
- **全链路认证**：`KerberosAuthenticator` 一站式完成 TGT → TGS → AP-REQ 流程
- **SPN 解析**：支持 `service/host@REALM` 格式，兼容 MIT krb5 NT_PRINCIPAL
- **微软 KDC 兼容**：PAC 请求、APPLICATION tag 扩展、AES256/AES128/RC4 加密
- 纯 Rust 实现，无外部运行时依赖

## 构建

```bash
git clone https://gitee.com/awol2010ex/rust-kinit
cd rust-kinit

cargo build            # 开发构建
cargo build --release  # 发布构建
```

## 使用方法

### kinit - 获取 TGT

```bash
kinit -kt <keytab文件> <principal@REALM>
kinit -kt hdfs.keytab hdfs@XXX.COM -o /tmp/krb5cc
```

**参数说明：**
- `-kt <file>`：keytab 文件路径（必需）
- `<principal@REALM>`：Kerberos principal（必需）
- `-o <file>`：输出 ccache 文件路径（可选，默认 `%TEMP%\krb5cc_<USERNAME>`）

### klist - 列出 ccache 内容

```bash
klist                          # 列出默认 ccache
klist -c D:\path\to\krb5cc     # 指定路径
klist -e                       # 显示加密类型详情
```

**参数说明：**
- `-c <path>`：指定 ccache 文件路径
- `-e`：显示 etype/keytype 详细信息
- 环境变量 `KRB5CCNAME` 可覆盖默认 ccache 路径（支持 `FILE:` 前缀）

### 全链路认证（编程接口）

`KerberosAuthenticator` 封装了完整的 TGT → TGS → AP-REQ 流程：

```rust
use kerbeiros::integration::{KerberosAuthenticator, KerberosAuthOptions};
use kerberos_crypto::Key;
use std::net::Ipv4Addr;

let options = KerberosAuthOptions {
    realm: "EXAMPLE.COM".parse().unwrap(),
    kdc_address: Ipv4Addr::new(192, 168, 1, 10).into(),
    username: "alice".parse().unwrap(),
    user_key: Key::Secret("password123".to_string()),
    service_principal: "thrift/server.example.com".parse().unwrap(),
    ..Default::default()
};

let authenticator = KerberosAuthenticator::new(options);
let ap_req_bytes = authenticator.authenticate().unwrap();
```

支持多种返回模式：
- `authenticate()` → 返回 AP-REQ bytes
- `authenticate_full()` → 返回 AP-REQ + Credential
- `authenticate_full_with_seq()` → 返回 AP-REQ + Credential + GSS 初始序列号
- `authenticate_full_with_seq_and_subkey()` → 返回含 subkey 的完整信息（兼容 Java JGSS）

### GSS 消息保护

JDK V2 格式 WRAP/MIC 令牌，适配 Thrift SASL 等场景：

```rust
use kerbeiros::gss_engine::KerberosGssEngine;

let mut engine = KerberosGssEngine::new_with_seq(session_key, 18, init_seq);
let wrapped = engine.wrap(b"hello world").unwrap();
let unwrapped = engine.unwrap(&wrapped).unwrap();
```

## 输出示例

```
Ticket cache: FILE:C:\Users\ADMINI~1\AppData\Local\Temp\krb5cc_Administrator
Default principal: hdfs@XXX.COM

 1. hdfs@XXX.COM
    krbtgt/XXX.COM@XXX.COM
    EType: aes256-cts-hmac-sha1-96
    Flags: Forwardable, Renewable, Initial, Name-canonicalize
    Auth Time:     2026-06-17 06:39:42
    Valid Starting:2026-06-17 06:39:42
    Expires:       2026-06-18 06:39:42
    Renew Till:    2026-06-24 06:39:42
```

## 项目结构

```
rust-kinit/
├── Cargo.toml              # Workspace 配置（含 [workspace.package] 统一配置）
├── LICENSE                 # AGPL-3.0
├── publish.ps1             # crates.io 发布脚本
├── crates/
│   ├── kinit-kt/           # kinit 命令行工具（awol2005ex3-kinit-kt）
│   ├── klist/              # klist 命令行工具（awol2005ex3-klist）
│   ├── kerbeiros/          # Kerberos 认证核心库（awol2005ex3-kerbeiros）
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── as_requester.rs         # AS-REQ 请求器
│   │   │   ├── tgt_requester.rs        # TGT 请求器包装
│   │   │   ├── tgs_requester.rs        # TGS 服务票据请求器
│   │   │   ├── integration.rs          # 全链路认证 KerberosAuthenticator
│   │   │   ├── gss_engine.rs           # GSS-API 消息保护引擎
│   │   │   ├── utils.rs                # 工具函数（本地IP、DNS解析）
│   │   │   ├── messages/
│   │   │   │   ├── asreq/              # AS-REQ 消息构建
│   │   │   │   └── ap_req.rs           # AP-REQ 消息构建器
│   │   │   └── credentials/
│   │   │       └── mappers/
│   │   │           └── credential_krb_info.rs  # KDC 凭据解密与映射
│   ├── kerberos-asn1/      # Kerberos ASN.1 类型定义（awol2005ex3-kerberos-asn1）
│   ├── kerberos-ccache/    # ccache 文件格式读写（awol2005ex3-kerberos-ccache）
│   ├── kerberos-constants/ # Kerberos 常量定义（awol2005ex3-kerberos-constants）
│   ├── kerberos-crypto/    # Kerberos 加密算法（awol2005ex3-kerberos-crypto）
│   │   └── src/
│   │       └── checksum.rs    # checksum 函数（HMAC-MD5、SHA-AES、SHA-AES-LE）
│   ├── kerberos-keytab/    # keytab 文件格式解析（awol2005ex3-kerberos-keytab）
│   ├── mit-krb5-ccache/    # MIT krb5 FCC v4 ccache 写入（awol2005ex3-mit-krb5-ccache）
│   ├── red-asn1/           # ASN.1 DER 编码/解码库（awol2005ex3-red-asn1）
│   └── red-asn1-derive/    # ASN.1 derive 宏（awol2005ex3-red-asn1-derive）
```

## 与 MIT kinit 的兼容性

- 默认 ccache 路径：`%TEMP%\krb5cc_<USERNAME>`（与 MIT Kerberos for Windows 一致）
- 支持 `KRB5CCNAME` 环境变量（自动 strip `FILE:` / `WRFILE:` 前缀）
- ccache 文件格式与 MIT Kerberos FCC v4 完全兼容
- TGS-REQ 使用 NT_PRINCIPAL name_type（MIT krb5 gss_accept_sec_context 要求）
- 微软 KDC 兼容：PA-PAC-REQUEST、APPLICATION tag 扩展、local address

## 技术细节

### 修复的 Bug

1. **etype 使用 KDC 实际值**：原实现使用 `key.etypes()[0]` 而非 `kdc_rep.enc_part.etype`，导致解密失败
2. **微软 KDC APPLICATION tag 兼容**：微软 KDC 返回的 `EncAsRepPart` 使用 tag `0x7a` 而非标准 `0x79`，已添加兼容处理
3. **KeyBlock::new() etype 硬编码**：`KeyBlock::new()` 将 `etype` 硬编码为 0，导致 klist 显示 `EType: null`

### Rust 2024 Edition 兼容修复

- 移除 `ref` 绑定模式（`kerberos-crypto`, `red-asn1-derive`）
- 转义保留关键字（`gen` → `r#gen` in `kerbeiros`）
- 修复 `chrono` 弃用方法（`Utc::ymd()` → `Utc.with_ymd_and_hms()` 等）

### GSS 引擎说明

`KerberosGssEngine` 实现 JDK V2 格式 GSS WRAP/MIC 令牌，特点：
- **令牌格式**：16 字节 MessageTokenHeader（TOK_ID + Flags + FILLER + EC + RRC + SND_SEQ）
- **Checksum**：SHA-1 HMAC (12B)，使用 4 种 key_usage（22/23/24/25）
- **Unwrap 策略**：自动尝试所有 4 种 key_usage 以兼容不同 JDK GSS 实现
- **序列号**：64-bit big-endian SND_SEQ，可重置

### 全链路认证流程

```
用户凭证 (keytab/password)
    ↓
AS-REQ → KDC → AS-REP          ← TGT 获取
    ↓
TGS-REQ → KDC → TGS-REP         ← 服务票据请求
    ↓
AP-REQ (Authenticator + 服务票据)  ← 应用层认证
    ↓
GSS WRAP/MIC                     ← 消息保护（可选）
```

## 许可证

[GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE)
