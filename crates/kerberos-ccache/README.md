# awol2005ex3-kerberos-ccache

Kerberos 凭据缓存（ccache）文件格式的读写库。支持解析和生成 ccache 数据结构。

修复了 `KeyBlock::new()` etype 硬编码为 0 的 bug。

## 用法

```rust
use kerberos_ccache::CCache;

let data = std::fs::read("krb5cc")?;
let ccache = CCache::parse(&data)?;
println!("Default principal: {}", ccache.default_principal);
```

## Crates.io

`awol2005ex3-kerberos-ccache`
