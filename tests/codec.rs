use lattice_multikey::{Error, KeyType, Multikey};

#[test]
fn all_registered_codes_match_swift_bytes() {
    for (kind, prefix) in [
        (KeyType::Ed25519, "ed01"),
        (KeyType::Secp256k1, "e701"),
        (KeyType::P256, "8024"),
        (KeyType::P384, "8124"),
        (KeyType::P521, "8224"),
        (KeyType::MlDsa44, "8524"),
        (KeyType::MlDsa65, "8724"),
        (KeyType::MlDsa87, "8824"),
    ] {
        for bytes in [vec![], vec![0, 255, 128], vec![42; 2592]] {
            let key = Multikey {
                key_type: kind,
                key_bytes: bytes,
            };
            assert!(key.hex_encoded().starts_with(prefix));
            assert_eq!(Multikey::decode(&key.encode()), Ok(key.clone()));
            assert_eq!(
                Multikey::from_hex(&format!("0x{}", key.hex_encoded().to_uppercase())),
                Ok(key)
            );
        }
    }
}
#[test]
fn malformed_inputs_fail_without_panicking() {
    assert_eq!(Multikey::decode(&[]), Err(Error::VarintTruncated));
    assert_eq!(Multikey::decode(&[0xed]), Err(Error::VarintTruncated));
    assert_eq!(Multikey::decode(&[0]), Err(Error::UnknownKeyType(0)));
    assert_eq!(Multikey::decode(&[255; 10]), Err(Error::VarintTruncated));
    let mut overflowing = vec![0xed, 0x81];
    overflowing.extend_from_slice(&[0x80; 7]);
    overflowing.push(2);
    assert_eq!(
        Multikey::decode_strict(&overflowing),
        Err(Error::VarintOverflow)
    );
    assert_eq!(
        Multikey::decode(&overflowing).unwrap().hex_encoded(),
        "ed01"
    );
    for s in ["e", "zz", "é", "0Xed01", " ed01", "ed01\n"] {
        assert_eq!(Multikey::from_hex(s), Err(Error::InvalidEncoding));
    }
}
#[test]
fn nonminimal_code_matches_reference_acceptance() {
    let decoded = Multikey::decode(&[0xed, 0x81, 0, 42]).unwrap();
    assert_eq!(decoded.hex_encoded(), "ed012a");
}

#[test]
fn matches_pinned_swift_codec() {
    let vectors = include_str!("swift-vectors.txt");
    assert_eq!(vectors.lines().count(), 48);
    for line in vectors.lines() {
        let (code, hex) = line.split_once(' ').unwrap();
        let kind = KeyType::try_from(code.parse::<u64>().unwrap()).unwrap();
        let decoded = Multikey::from_hex(hex).unwrap();
        assert_eq!(decoded.key_type, kind);
        assert_eq!(decoded.hex_encoded(), hex);
        assert!(decoded
            .key_bytes
            .iter()
            .enumerate()
            .all(|(i, b)| *b == (i % 256) as u8));
    }
}

#[test]
fn malformed_and_nonminimal_verdicts_match_unchanged_swift() {
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("swift-malformed.json")).unwrap();
    assert_eq!(rows.len(), 297);
    for row in rows {
        let input = row["input"].as_str().unwrap();
        let actual = match Multikey::from_hex(input) {
            Ok(key) => key.hex_encoded(),
            Err(Error::UnknownKeyType(code)) => format!("error:unknownKeyType({code})"),
            Err(Error::InvalidEncoding) => "error:invalidEncoding".into(),
            Err(Error::VarintOverflow) => "error:varintOverflow".into(),
            Err(Error::VarintTruncated) => "error:varintTruncated".into(),
        };
        assert_eq!(actual, row["result"].as_str().unwrap(), "input {input}");
    }
    assert_eq!(
        Multikey::from_hex_strict("ed01+1"),
        Err(Error::InvalidEncoding)
    );
    assert_eq!(
        Multikey::from_hex_strict("ed01-0"),
        Err(Error::InvalidEncoding)
    );
}
