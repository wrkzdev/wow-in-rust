use super::*;

fn sect(pairs: &[(&str, Value)]) -> Section {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect()
}

#[test]
fn header_is_the_documented_nine_bytes() {
    // specs/04 §2.2: signature A, signature B, version -- as little-endian u32s.
    let mut expect = Vec::new();
    expect.extend_from_slice(&SIGNATURE_A.to_le_bytes());
    expect.extend_from_slice(&SIGNATURE_B.to_le_bytes());
    expect.push(FORMAT_VERSION);
    assert_eq!(&HEADER[..], &expect[..]);
    assert_eq!(
        crate::epee::HEADER,
        [0x01, 0x11, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01]
    );
}

#[test]
fn rejects_a_bad_signature() {
    let mut b = HEADER.to_vec();
    b.push(0);
    assert!(from_bytes(&b).is_ok());

    let mut bad = HEADER;
    bad[0] = 0x02;
    let mut b = bad.to_vec();
    b.push(0);
    assert!(matches!(from_bytes(&b), Err(Error::BadEpeeSignature)));

    assert!(matches!(from_bytes(&[]), Err(Error::UnexpectedEof)));
    assert!(matches!(
        from_bytes(&HEADER[..5]),
        Err(Error::UnexpectedEof)
    ));
}

#[test]
fn roundtrips_every_scalar_type() {
    let s = sect(&[
        ("i64", Value::I64(-9_000_000_000)),
        ("i32", Value::I32(-70_000)),
        ("i16", Value::I16(-300)),
        ("i8", Value::I8(-5)),
        ("u64", Value::U64(u64::MAX)),
        ("u32", Value::U32(u32::MAX)),
        ("u16", Value::U16(u16::MAX)),
        ("u8", Value::U8(u8::MAX)),
        ("f", Value::Double(-1.5e300)),
        ("b_true", Value::Bool(true)),
        ("b_false", Value::Bool(false)),
        ("s", Value::String(b"\x00\xffbinary".to_vec())),
        ("empty", Value::String(Vec::new())),
    ]);
    let blob = to_bytes(&s).unwrap();
    assert_eq!(blob.len(), 9 + encoded_len(&s).unwrap());
    assert_eq!(from_bytes(&blob).unwrap(), s);
}

#[test]
fn roundtrips_nested_objects_and_arrays() {
    let inner = sect(&[("x", Value::U32(7))]);
    let s = sect(&[
        ("obj", Value::Object(inner.clone())),
        (
            "nums",
            Value::Array(Array {
                elem_type: ty::UINT64,
                items: vec![Value::U64(1), Value::U64(2), Value::U64(3)],
            }),
        ),
        (
            "strs",
            Value::Array(Array {
                elem_type: ty::STRING,
                items: vec![Value::String(b"a".to_vec()), Value::String(b"bb".to_vec())],
            }),
        ),
        // The C wraps an inner array in an object; that shape must round-trip.
        (
            "objs",
            Value::Array(Array {
                elem_type: ty::OBJECT,
                items: vec![Value::Object(inner.clone()), Value::Object(inner)],
            }),
        ),
        (
            "empty_arr",
            Value::Array(Array {
                elem_type: ty::UINT8,
                items: vec![],
            }),
        ),
    ]);
    let blob = to_bytes(&s).unwrap();
    assert_eq!(blob.len(), 9 + encoded_len(&s).unwrap());
    assert_eq!(from_bytes(&blob).unwrap(), s);
}

/// `specs/04` §2.7: unknown entry names MUST be skipped, not rejected. This is
/// how the protocol evolves — a newer peer sending a field we do not know must
/// not drop the connection.
#[test]
fn unknown_entries_are_preserved_not_rejected() {
    let s = sect(&[
        ("known", Value::U64(1)),
        ("some_future_field", Value::String(b"whatever".to_vec())),
    ]);
    let blob = to_bytes(&s).unwrap();
    let got = from_bytes(&blob).unwrap();
    assert_eq!(got.u64("known").unwrap(), 1);
    // Reading only what we understand leaves the rest untouched.
    assert!(got.contains_key("some_future_field"));
}

/// `KV_SERIALIZE_OPT`: a peer that omits `pruning_seed` or `rpc_port` is fine,
/// and the reader must supply the default rather than erroring.
#[test]
fn opt_fields_default_when_absent() {
    let s = sect(&[("id", Value::U64(42))]);
    assert_eq!(s.opt_u64("pruning_seed", 0).unwrap(), 0);
    assert_eq!(s.opt_u64("rpc_port", 0).unwrap(), 0);
    // NOTIFY_NEW_TRANSACTIONS.dandelionpp_fluff defaults to TRUE (specs/08 §7.1).
    assert!(s.opt_bool("dandelionpp_fluff", true).unwrap());
    assert_eq!(s.u64("id").unwrap(), 42);
    assert!(matches!(s.u64("nope"), Err(Error::MissingField("nope"))));
}

#[test]
fn type_mismatch_on_a_known_field_is_an_error() {
    let s = sect(&[("n", Value::String(b"not a number".to_vec()))]);
    assert!(matches!(
        s.u64("n"),
        Err(Error::TypeMismatch {
            field: "n",
            expected: "unsigned integer"
        })
    ));
}

/// `KV_SERIALIZE` picks the narrowest integer type that fits, so a `uint64_t`
/// field can legitimately arrive as UINT8.
#[test]
fn narrower_unsigned_types_widen() {
    for v in [Value::U8(7), Value::U16(7), Value::U32(7), Value::U64(7)] {
        let s = sect(&[("h", v)]);
        assert_eq!(s.u64("h").unwrap(), 7);
    }
}

/// `KV_SERIALIZE_VAL_POD_AS_BLOB` is a STRING of exactly `sizeof(T)` bytes.
#[test]
fn pod_as_blob_checks_its_length() {
    let s = sect(&[("network_id", Value::String(vec![0xaa; 16]))]);
    assert_eq!(s.pod::<16>("network_id").unwrap(), [0xaa; 16]);
    assert!(matches!(
        s.pod::<32>("network_id"),
        Err(Error::BadPodBlobLength { len: 16, elem: 32 })
    ));
}

/// `specs/04` §2.6: `CONTAINER_POD_AS_BLOB` is why `NOTIFY_REQUEST_CHAIN.
/// block_ids` arrives as one string of `32 * n` bytes, not an array of strings.
#[test]
fn container_pod_as_blob_splits_and_validates() {
    let hashes: Vec<[u8; 32]> = (0u8..3).map(|i| [i; 32]).collect();
    let v = pod_container(hashes.iter().map(|h| &h[..]));
    assert_eq!(v.as_bytes().unwrap().len(), 96);

    let parts = v.as_pod_container(32).unwrap();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[2], &[2u8; 32][..]);

    // A length that is not a multiple of the element size is an error.
    let bad = Value::String(vec![0u8; 33]);
    assert!(matches!(
        bad.as_pod_container(32),
        Err(Error::BadPodBlobLength { len: 33, elem: 32 })
    ));
    // An empty container is legal and yields no elements.
    assert!(Value::String(vec![])
        .as_pod_container(32)
        .unwrap()
        .is_empty());
}

/// The single highest-risk parser in the project faces the network before any
/// authentication. A tiny message must not be able to make it allocate.
#[test]
fn a_huge_declared_count_does_not_allocate() {
    // Header, then a section claiming 2^30 entries, with nothing following.
    let mut blob = HEADER.to_vec();
    varint::write_epee_varint(&mut blob, 1_000_000_000).unwrap();
    assert!(matches!(from_bytes(&blob), Err(Error::UnexpectedEof)));

    // One entry whose STRING claims 2^30 bytes.
    let mut blob = HEADER.to_vec();
    varint::write_epee_varint(&mut blob, 1).unwrap();
    blob.push(1);
    blob.push(b'x');
    blob.push(ty::STRING);
    varint::write_epee_varint(&mut blob, 1_000_000_000).unwrap();
    assert!(matches!(from_bytes(&blob), Err(Error::UnexpectedEof)));

    // An array claiming 2^30 elements.
    let mut blob = HEADER.to_vec();
    varint::write_epee_varint(&mut blob, 1).unwrap();
    blob.push(1);
    blob.push(b'x');
    blob.push(ty::UINT64 | ty::ARRAY_FLAG);
    varint::write_epee_varint(&mut blob, 1_000_000_000).unwrap();
    assert!(matches!(from_bytes(&blob), Err(Error::UnexpectedEof)));
}

#[test]
fn nesting_is_capped() {
    // Build RECURSION_LIMIT + 2 nested single-entry objects.
    let mut blob = HEADER.to_vec();
    for _ in 0..(RECURSION_LIMIT + 2) {
        varint::write_epee_varint(&mut blob, 1).unwrap();
        blob.push(1);
        blob.push(b'o');
        blob.push(ty::OBJECT);
    }
    varint::write_epee_varint(&mut blob, 0).unwrap();
    assert!(matches!(from_bytes(&blob), Err(Error::RecursionLimit)));

    // Just under the limit is fine.
    let mut blob = HEADER.to_vec();
    for _ in 0..(RECURSION_LIMIT - 2) {
        varint::write_epee_varint(&mut blob, 1).unwrap();
        blob.push(1);
        blob.push(b'o');
        blob.push(ty::OBJECT);
    }
    varint::write_epee_varint(&mut blob, 0).unwrap();
    assert!(from_bytes(&blob).is_ok());
}

#[test]
fn unknown_type_bytes_are_rejected() {
    let mut blob = HEADER.to_vec();
    varint::write_epee_varint(&mut blob, 1).unwrap();
    blob.push(1);
    blob.push(b'x');
    blob.push(!ty::ARRAY_FLAG); // 0x7f: no array flag, and no such scalar type
    assert!(matches!(
        from_bytes(&blob),
        Err(Error::UnknownEpeeType(0x7f))
    ));

    // Standalone ARRAY (13) is not used by Monero/Wownero -- specs/04 §2.5.
    let mut blob = HEADER.to_vec();
    varint::write_epee_varint(&mut blob, 1).unwrap();
    blob.push(1);
    blob.push(b'x');
    blob.push(ty::ARRAY);
    assert!(matches!(from_bytes(&blob), Err(Error::UnknownEpeeType(13))));
}

#[test]
fn writer_rejects_shapes_the_format_cannot_express() {
    // Nested arrays are impossible directly.
    let s = sect(&[(
        "a",
        Value::Array(Array {
            elem_type: ty::UINT8,
            items: vec![Value::Array(Array {
                elem_type: ty::UINT8,
                items: vec![],
            })],
        }),
    )]);
    assert!(to_bytes(&s).is_err());

    // A heterogeneous array has no wire form: there is one type byte.
    let s = sect(&[(
        "a",
        Value::Array(Array {
            elem_type: ty::UINT8,
            items: vec![Value::U8(1), Value::U64(2)],
        }),
    )]);
    assert!(matches!(
        to_bytes(&s),
        Err(Error::InvalidValue("heterogeneous epee array"))
    ));

    // Entry names are length-prefixed with a single byte.
    let mut s = Section::new();
    s.insert("n".repeat(256), Value::U8(0));
    assert!(matches!(to_bytes(&s), Err(Error::NameTooLong)));
}

/// `specs/15` §4.4: never panic. Truncating a valid message at every offset,
/// and flipping every byte, must yield `Err` or `Ok` but never unwind.
#[test]
fn never_panics_on_malformed_input() {
    let inner = sect(&[("x", Value::U32(7)), ("y", Value::String(vec![1, 2, 3]))]);
    let s = sect(&[
        ("obj", Value::Object(inner)),
        (
            "arr",
            Value::Array(Array {
                elem_type: ty::UINT64,
                items: vec![Value::U64(1), Value::U64(2)],
            }),
        ),
        ("b", Value::Bool(true)),
        ("d", Value::Double(1.0)),
    ]);
    let blob = to_bytes(&s).unwrap();

    for cut in 0..blob.len() {
        let _ = from_bytes(&blob[..cut]);
    }
    for i in 0..blob.len() {
        for bit in 0..8 {
            let mut m = blob.clone();
            m[i] ^= 1 << bit;
            let _ = from_bytes(&m);
        }
    }
    // Pure noise.
    let mut x: u64 = 0x1234_5678_9abc_def0;
    for len in 0..200usize {
        let mut noise = HEADER.to_vec();
        for _ in 0..len {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            noise.push((x >> 33) as u8);
        }
        let _ = from_bytes(&noise);
    }
}

/// Re-encoding a parsed message must reproduce the bytes. With a `BTreeMap` the
/// entry order is canonical, so this holds for anything we wrote ourselves and
/// for any peer message whose entries were already sorted.
#[test]
fn reencode_is_stable() {
    let s = sect(&[
        ("a", Value::U64(1)),
        ("b", Value::String(vec![9; 40])),
        ("c", Value::Object(sect(&[("d", Value::Bool(false))]))),
    ]);
    let blob = to_bytes(&s).unwrap();
    let parsed = from_bytes(&blob).unwrap();
    assert_eq!(to_bytes(&parsed).unwrap(), blob);
}
