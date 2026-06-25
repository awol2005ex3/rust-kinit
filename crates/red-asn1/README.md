# awol2005ex3-red-asn1

ASN.1 DER 编码/解码库。支持 INTEGER、OCTET STRING、SEQUENCE、Enumerated、BitString、
GeneralizedTime 等 ASN.1 基本类型。基于 `nom` 解析器。

## 用法

```rust
use red_asn1::{Asn1Object, Integer};

let data = Integer::new(42).encode();
let decoded = Integer::parse(&data)?;
assert_eq!(decoded.value(), 42);
```

## Crates.io

`awol2005ex3-red-asn1`
