# awol2005ex3-kerbeiros

Kerberos AS-REQ/AS-REP 协议实现。发送 AS-REQ 请求并解析 AS-REP 响应，获取 TGT。

修复了原始 `himmelblau_kerbeiros` 的两个 bug：
- etype 改用 `kdc_rep.enc_part.etype`（而非 `key.etypes()[0]`）
- 兼容微软 KDC 的 APPLICATION tag `0x7a` → `0x79`

## 用法

```rust
use kerbeiros::TgtRequester;

let requester = TgtRequester::new()?;
let credential = requester.request_tgt(&keytab, "hdfs@REALM.COM")?;
```

## Crates.io

`awol2005ex3-kerbeiros`
