//! Multicodec public-key envelopes compatible with 0xLattice/Multikey.
//! This codec does not validate cryptographic keys or enforce key lengths.
#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum KeyType {
    Ed25519 = 0xed,
    Secp256k1 = 0xe7,
    P256 = 0x1200,
    P384 = 0x1201,
    P521 = 0x1202,
    MlDsa44 = 0x1205,
    MlDsa65 = 0x1207,
    MlDsa87 = 0x1208,
}

impl KeyType {
    pub fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::Secp256k1 => "secp256k1",
            Self::P256 => "p256",
            Self::P384 => "p384",
            Self::P521 => "p521",
            Self::MlDsa44 => "ml-dsa-44",
            Self::MlDsa65 => "ml-dsa-65",
            Self::MlDsa87 => "ml-dsa-87",
        }
    }
}

impl TryFrom<u64> for KeyType {
    type Error = Error;
    fn try_from(value: u64) -> Result<Self, Error> {
        Ok(match value {
            0xed => Self::Ed25519,
            0xe7 => Self::Secp256k1,
            0x1200 => Self::P256,
            0x1201 => Self::P384,
            0x1202 => Self::P521,
            0x1205 => Self::MlDsa44,
            0x1207 => Self::MlDsa65,
            0x1208 => Self::MlDsa87,
            other => return Err(Error::UnknownKeyType(other)),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    UnknownKeyType(u64),
    InvalidEncoding,
    VarintOverflow,
    VarintTruncated,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Multikey {
    pub key_type: KeyType,
    pub key_bytes: Vec<u8>,
}

impl Multikey {
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = unsigned_varint::encode::u64_buffer();
        let prefix = unsigned_varint::encode::u64(self.key_type as u64, &mut buffer);
        let mut result = Vec::with_capacity(prefix.len() + self.key_bytes.len());
        result.extend_from_slice(prefix);
        result.extend_from_slice(&self.key_bytes);
        result
    }

    pub fn hex_encoded(&self) -> String {
        self.encode().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Like Swift, accepts overlong (non-minimal) encodings of known codes.
    /// Matches Swift truncation of high bits in the tenth byte.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut code = 0u64;
        for (index, &byte) in data.iter().enumerate() {
            if index >= 10 {
                return Err(Error::VarintOverflow);
            }
            code |= u64::from(byte & 127) << (index * 7);
            if byte & 128 == 0 {
                return Ok(Self {
                    key_type: code.try_into()?,
                    key_bytes: data[index + 1..].to_vec(),
                });
            }
        }
        Err(Error::VarintTruncated)
    }

    /// Opt-in stricter envelope parsing for applications outside consensus.
    /// Rejects discarded bits and continuation in the tenth varint byte.
    pub fn decode_strict(data: &[u8]) -> Result<Self, Error> {
        for (index, &byte) in data.iter().enumerate() {
            if index >= 10 || (index == 9 && byte > 1) {
                return Err(Error::VarintOverflow);
            }
            if byte & 128 == 0 {
                break;
            }
        }
        Self::decode(data)
    }

    /// Swift UInt8(radix:16) accepts a leading plus and negative zero in
    /// each two-character pair. Canonical signature checks remain separate.
    pub fn from_hex(text: &str) -> Result<Self, Error> {
        Self::decode(&hex_bytes(text, false)?)
    }

    pub fn from_hex_strict(text: &str) -> Result<Self, Error> {
        Self::decode_strict(&hex_bytes(text, true)?)
    }
}

fn hex_bytes(text: &str, strict: bool) -> Result<Vec<u8>, Error> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    if !text.is_ascii() || !text.len().is_multiple_of(2) {
        return Err(Error::InvalidEncoding);
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            let pair = &text[i..i + 2];
            if !strict && pair == "-0" {
                return Ok(0);
            }
            if strict && !pair.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::InvalidEncoding);
            }
            u8::from_str_radix(pair, 16).map_err(|_| Error::InvalidEncoding)
        })
        .collect()
}
