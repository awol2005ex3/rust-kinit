# awol2005ex3-mit-krb5-ccache

MIT Kerberos FCC（File Credential Cache）v4 格式的写入库。生成与 MIT krb5 完全兼容的二进制 ccache 文件。

## 用法

```rust
use mit_krb5_ccache::{CCache, Principal, Credential, KeyBlock, Times};

let ccache = CCache {
    default_principal: Principal { /* ... */ },
    credentials: vec![Credential { /* ... */ }],
};
let bytes = ccache.encode();
std::fs::write("krb5cc", bytes)?;
```

## Crates.io

`awol2005ex3-mit-krb5-ccache`
