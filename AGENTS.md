# AGENTS.md - rust-kinit 开发规范与辅助文档

> 本文档供 AI Agent 在参与 rust-kinit 项目开发时参考。
> 包含项目结构、关键决策、编码规范、测试指南等。

---

## 项目概述

Rust 实现的 Kerberos `kinit` / `klist` 命令行工具，用于通过 keytab 文件获取 TGT 并管理 Kerberos 凭据缓存（ccache）。

**当前状态**：功能基本完成，kinit + klist 均可用，已修复上游 bug，Rust 2024 edition 兼容。所有 crate 已发布到 [crates.io](https://crates.io)（`awol2005ex3-*` 前缀）。

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
│   ├── kerbeiros/            # Kerberos AS-REQ/AS-REP 实现（awol2005ex3-kerbeiros）
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── as_requester.rs      # AsRequester 接口
│   │       ├── tgt_requester.rs    # TgtRequester 包装
│   │       └── credentials/
│   │           └── mappers/
│   │               └── credential_krb_info.rs  # [已修复] etype bug + 微软 KDC tag 兼容
│   ├── kerberos-asn1/       # Kerberos ASN.1 类型定义（awol2005ex3-kerberos-asn1）
│   ├── kerberos-ccache/     # ccache 文件格式读写（awol2005ex3-kerberos-ccache）
│   │   └── src/
│   │       ├── key_block.rs  # [已修复] KeyBlock::new() etype 硬编码 bug
│   │       └── credential.rs
│   ├── kerberos-constants/  # Kerberos 常量定义（awol2005ex3-kerberos-constants）
│   ├── kerberos-crypto/     # Kerberos 加密算法（awol2005ex3-kerberos-crypto）
│   ├── kerberos-keytab/    # keytab 文件格式解析（awol2005ex3-kerberos-keytab）
│   ├── mit-krb5-ccache/    # MIT krb5 FCC v4 ccache 写入（awol2005ex3-mit-krb5-ccache）
│   ├── red-asn1/            # ASN.1 DER 编码/解码库（awol2005ex3-red-asn1）
│   └── red-asn1-derive/     # ASN.1 derive 宏（awol2005ex3-red-asn1-derive）
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

### 已知问题

1. **错误信息用中文**: 部分错误信息是中文（kinit-kt, mit-krb5-ccache 等），如需国际化需重构

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

---

## 许可证

本项目采用 **AGPL-3.0**（GNU Affero General Public License v3.0）开源协议（包括 `mit-krb5-ccache`）。
