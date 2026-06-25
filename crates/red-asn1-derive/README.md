# awol2005ex3-red-asn1-derive

`red-asn1` 的 derive 宏（proc-macro）。通过 `#[derive(Sequence)]` 自动为结构体生成 ASN.1 SEQUENCE 的 DER 编码/解码实现。

## 用法

```rust
use red_asn1::{Asn1Object, Integer, OctetString};
use red_asn1_derive::Sequence;

#[derive(Sequence)]
struct MyStruct {
    field1: Integer,
    field2: OctetString,
}
```

## Crates.io

`awol2005ex3-red-asn1-derive`
