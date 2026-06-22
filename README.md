# rust-kinit

Rust 实现的 Kerberos `kinit` / `klist` 命令行工具，用于通过 keytab 文件获取 TGT（Ticket Granting Ticket）并管理 Kerberos 凭据缓存（ccache）。

## 功能特性

- **kinit**：通过 keytab 文件获取 TGT，兼容 MIT kinit 行为
- **klist**：列出 ccache 中的 Kerberos 凭据信息
- 支持 AES256/AES128/RC4 加密类型
- 兼容微软 KDC 的 APPLICATION tag 扩展
- ccache 默认路径与 MIT Kerberos for Windows 一致（`%TEMP%\krb5cc_<USERNAME>`）
- 纯 Rust 实现，无运行时依赖

## 构建

```bash
# 克隆仓库
git clone <repo-url>
cd rust-kinit

# 开发构建
cargo build

# 发布构建（推荐）
cargo build --release

# 构建产物位置
#   D:\cargo-target\release\kinit.exe
#   D:\cargo-target\release\klist.exe
```

## 使用方法

### kinit - 获取 TGT

```bash
# 基本用法
kinit -kt <keytab文件> <principal@REALM>

# 指定输出 ccache 路径
kinit -kt hdfs.keytab hdfs@XXX.COM -o /tmp/krb5cc

# 示例
kinit -kt "D:\path\to\hdfs.keytab" hdfs@XXX.COM
```

**参数说明：**
- `-kt <file>`：keytab 文件路径（必需）
- `<principal@REALM>`：Kerberos principal（必需）
- `-o <file>`：输出 ccache 文件路径（可选，默认 `%TEMP%\krb5cc_<USERNAME>`）

### klist - 列出 ccache 内容

```bash
# 列出默认 ccache（%TEMP%\krb5cc_<USERNAME>）
klist

# 指定 ccache 路径
klist -c D:\path\to\krb5cc_hdfs

# 显示加密类型详情
klist -e

# 组合使用
klist -e -c D:\path\to\krb5cc_hdfs
```

**参数说明：**
- `-c <path>`：指定 ccache 文件路径
- `-e`：显示 etype/keytype 详细信息
- 环境变量 `KRB5CCNAME` 可覆盖默认 ccache 路径（支持 `FILE:` 前缀）

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
├── Cargo.toml              # Workspace 配置
├── crates/
│   ├── kinit-kt/           # kinit 命令行工具
│   ├── klist/              # klist 命令行工具
│   ├── kerbeiros/          # Kerberos AS-REQ/AS-REP 实现（已修复）
│   ├── kerberos-asn1/      # Kerberos ASN.1 类型定义
│   ├── kerberos-ccache/    # ccache 文件格式读写
│   ├── kerberos-constants/ # Kerberos 常量定义
│   ├── kerberos-crypto/    # Kerberos 加密算法实现
│   ├── kerberos-keytab/    # keytab 文件格式解析
│   ├── red-asn1/           # ASN.1 DER 编码/解码库
│   └── red-asn1-derive/    # ASN.1 derive 宏（proc-macro）
```

## 与 MIT kinit 的兼容性

- 默认 ccache 路径：`%TEMP%\krb5cc_<USERNAME>`（与 MIT Kerberos for Windows 一致）
- 支持 `KRB5CCNAME` 环境变量（自动 strip `FILE:` / `WRFILE:` 前缀）
- ccache 文件格式与 MIT Kerberos 完全兼容

## 技术细节

### 修复的上游 Bug

1. **etype 使用 KDC 实际值**：原 `himmelblau_kerbeiros` 使用 `key.etypes()[0]` 而非 `kdc_rep.enc_part.etype`，导致解密失败
2. **微软 KDC APPLICATION tag 兼容**：微软 KDC 返回的 `EncAsRepPart` 使用 tag `0x7a` 而非标准 `0x79`，已添加兼容处理

### Rust 2024 Edition 兼容修复

- 移除 `ref` 绑定模式（`kerberos-crypto`, `red-asn1-derive`）
- 转义保留关键字（`gen` → `r#gen` in `kerbeiros`）
- 修复 `chrono` 弃用方法（`Utc::ymd()` → `Utc.with_ymd_and_hms()` 等）

## 许可证

本项目采用 [GNU Affero General Public License v3.0 (AGPL-3.0)](https://opensource.org/licenses/AGPL-3.0) 开源协议。

如需与其他许可证合作，请联系维护者。
