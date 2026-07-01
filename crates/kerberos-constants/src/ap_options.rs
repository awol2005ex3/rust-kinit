// RFC 4120: KerberosFlags is a BIT STRING with big-endian bytes.
// Bit positions: reserved(0), use-session-key(1), mutual-required(2).
// In u32 big-endian, bit N = 1 << (31 - N).
pub const RESERVED: u32 = 0x80000000;
pub const USE_SESSION_KEY: u32 = 0x40000000;
pub const MUTUAL_REQUIRED: u32 = 0x20000000;
