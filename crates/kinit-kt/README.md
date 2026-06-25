# awol2005ex3-kinit-kt

通过 keytab 文件获取 Kerberos TGT 并写入 ccache。

## 命令行用法

```bash
kinit -kt <keytab> <principal@REALM> [-o <ccache>]
```

## 库用法

```rust
use kinit_kt::request_tgt;

let ccache_data = request_tgt("path/to/keytab", "hdfs@REALM.COM", None)?;
std::fs::write("krb5cc", ccache_data)?;
```

## Crates.io

`awol2005ex3-kinit-kt`
