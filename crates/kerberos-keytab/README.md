# awol2005ex3-kerberos-keytab

Kerberos keytab 文件格式解析库。支持 MIT keytab 格式（类型 1 和类型 2）。

## 用法

```rust
use kerberos_keytab::Keytab;

let data = std::fs::read("hdfs.keytab")?;
let keytab = Keytab::parse(&data)?;
for entry in &keytab.entries {
    println!("{}@{} (kvno={})", entry.principal, entry.realm, entry.kvno);
}
```

## Crates.io

`awol2005ex3-kerberos-keytab`
