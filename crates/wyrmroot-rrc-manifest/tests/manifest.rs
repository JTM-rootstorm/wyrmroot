#![cfg(feature = "builder")]

use wyrmroot_rrc_manifest::{
    Activation, DependencyKind, EDGE_RECORD_SIZE, ExpectedClosureEntry, ExpectedClosureUse,
    ExpectedObservedIdentity, HEADER_SIZE, ImmutableDependencyKind, MAX_EDGES, MAX_TOTAL_BYTES,
    Manifest, MaterialResidence, ObservedRetainedMaterial, ParseError, ProductError,
    ProductReceiptIdentities, ROLE_RECORD_SIZE, RoleId, StartupProfile, Wyr1aProductProfile,
    builder::{BuildError, Builder, DependencySpec, RoleSpec},
};

const BOOT_IDENTITY: [u8; 32] = [0x42; 32];
const INIT_IDENTITY: [u8; 32] = [0x99; 32];
const INIT_RUNTIME_IDENTITY: [u8; 32] = [0x98; 32];
const MANIFEST_RECEIPT_IDENTITY: [u8; 32] = [0xa1; 32];
const BOOTFS_RECEIPT_IDENTITY: [u8; 32] = [0xb1; 32];
const EMPTY_EDGE_GOLDEN_HEX: &str = "5752524d01000000500060002000000000000000d1000000010000002100000050000000b0000000b000000000000000424242424242424242424242424242424242424242424242424242424242424201000000030000000100010001000100000000001000000010000000110000000000000000000000111111111111111111111111111111111111111111111111111111111111111100000000000000000000000000000000000000000000000073797374656d2f7265676973747279646d696e696d756d20646973636f76657279";
const FULL_FIVE_ROLE_GOLDEN_HEX: &str = "5752524d01000000500060002000000000000000c903000005000400190100005000000030020000b002000000000000424242424242424242424242424242424242424242424242424242424242424201000000030000000100010001000100000000001000000010000000310000000000000000000000111111111111111111111111111111111111111111111111111111111111111100000000000000000000000000000000000000000000000002000000030000000100010001000100410000000d0000004e000000280000000000010000000000222222222222222222222222222222222222222222222222222222222222222200000000000000000000000000000000000000000000000003000000030000000100020001000000760000001100000087000000270000000100010000000000333333333333333333333333333333333333333333333333333333333333333300000000000000000000000000000000000000000000000004000000030000000100030001000000ae0000000f000000bd0000002b0000000200010000000000444444444444444444444444444444444444444444444444444444444444444400000000000000000000000000000000000000000000000005000000030000000100030001000000e80000000d000000f50000002400000003000100000000005555555555555555555555555555555555555555555555555555555555555555000000000000000000000000000000000000000000000000020000000500010001000000190100000000000000000000000000000000000003000000050001000200000019010000000000000000000000000000000000000400000005000100030000001901000000000000000000000000000000000000050000000500010004000000190100000000000000000000000000000000000073797374656d2f7265676973747279646d696e696d756d20626f6f74667320646973636f7665727920666f72207265636f7665727920636f6e6e656374696f6e7373797374656d2f6465766d6772726f6f742d637269746963616c206465766963652062696e64696e6720616e64207265737461727473797374656d2f7561727431363535306473656c656374656420713335207265636f766572792d636f6e736f6c65207472616e73706f727473797374656d2f636f6e736f6c6564626f756e646564206465677261646564206f70657261746f722d636f6e74726f6c207472616e73706f727473797374656d2f7779726d73686d696e696d756d207265636f766572792061646d696e697374726174696f6e2070617468";

fn role<'a>(id: RoleId, path: &'a str, justification: &'a str, byte: u8) -> RoleSpec<'a> {
    let (activation, startup_profile) = match id {
        RoleId::Registryd | RoleId::Devmgr => (Activation::Early, StartupProfile::EarlyBootStub),
        RoleId::Uart16550d => (Activation::DeviceBound, StartupProfile::Retained),
        RoleId::Consoled | RoleId::Wyrmsh => (Activation::ConsoleBound, StartupProfile::Retained),
    };
    RoleSpec {
        id,
        required: true,
        requires_ready: true,
        activation,
        startup_profile,
        path,
        justification,
        executable_identity: [byte; 32],
    }
}

fn product_roles() -> [RoleSpec<'static>; 5] {
    [
        role(
            RoleId::Registryd,
            "system/registryd",
            "minimum bootfs discovery for recovery connections",
            0x11,
        ),
        role(
            RoleId::Devmgr,
            "system/devmgr",
            "root-critical device binding and restart",
            0x22,
        ),
        role(
            RoleId::Uart16550d,
            "system/uart16550d",
            "selected q35 recovery-console transport",
            0x33,
        ),
        role(
            RoleId::Consoled,
            "system/consoled",
            "bounded degraded operator-control transport",
            0x44,
        ),
        role(
            RoleId::Wyrmsh,
            "system/wyrmsh",
            "minimum recovery administration path",
            0x55,
        ),
    ]
}

fn ready(owner: RoleId, target: RoleId) -> DependencySpec<'static> {
    DependencySpec {
        owner,
        kind: DependencyKind::RoleReady,
        target_role: Some(target),
        target_path: None,
    }
}

fn product_edges() -> [DependencySpec<'static>; 4] {
    [
        ready(RoleId::Devmgr, RoleId::Registryd),
        ready(RoleId::Uart16550d, RoleId::Devmgr),
        ready(RoleId::Consoled, RoleId::Uart16550d),
        ready(RoleId::Wyrmsh, RoleId::Consoled),
    ]
}

fn product_builder(reverse: bool) -> Builder<'static> {
    let mut builder = Builder::new(BOOT_IDENTITY);
    if reverse {
        for role in product_roles().into_iter().rev() {
            builder.add_role(role).unwrap();
        }
        for edge in product_edges().into_iter().rev() {
            builder.add_dependency(edge).unwrap();
        }
    } else {
        for role in product_roles() {
            builder.add_role(role).unwrap();
        }
        for edge in product_edges() {
            builder.add_dependency(edge).unwrap();
        }
    }
    builder
}

fn observed_material(path: &'static str, byte: u8) -> ObservedRetainedMaterial<'static> {
    ObservedRetainedMaterial {
        path,
        identity: [byte; 32],
        residence: MaterialResidence::RetainedBootfs,
    }
}

fn expected_product_closure() -> Vec<ExpectedClosureEntry<'static>> {
    vec![
        expected_role("system/consoled", 0x44, RoleId::Consoled),
        expected_role("system/devmgr", 0x22, RoleId::Devmgr),
        ExpectedClosureEntry {
            path: "system/init",
            identity: INIT_IDENTITY,
            usage: ExpectedClosureUse::SystemInit,
        },
        expected_role("system/registryd", 0x11, RoleId::Registryd),
        ExpectedClosureEntry {
            path: "system/runtime/init-parser",
            identity: INIT_RUNTIME_IDENTITY,
            usage: ExpectedClosureUse::InitDependency {
                kind: ImmutableDependencyKind::Runtime,
            },
        },
        expected_role("system/uart16550d", 0x33, RoleId::Uart16550d),
        expected_role("system/wyrmsh", 0x55, RoleId::Wyrmsh),
    ]
}

fn expected_role(path: &'static str, byte: u8, role: RoleId) -> ExpectedClosureEntry<'static> {
    ExpectedClosureEntry {
        path,
        identity: [byte; 32],
        usage: ExpectedClosureUse::RoleExecutable { role },
    }
}

fn observed_product_materials() -> Vec<ObservedRetainedMaterial<'static>> {
    vec![
        observed_material("system/consoled", 0x44),
        observed_material("system/devmgr", 0x22),
        ObservedRetainedMaterial {
            path: "system/init",
            identity: INIT_IDENTITY,
            residence: MaterialResidence::RetainedBootfs,
        },
        observed_material("system/registryd", 0x11),
        ObservedRetainedMaterial {
            path: "system/runtime/init-parser",
            identity: INIT_RUNTIME_IDENTITY,
            residence: MaterialResidence::RetainedBootfs,
        },
        observed_material("system/uart16550d", 0x33),
        observed_material("system/wyrmsh", 0x55),
    ]
}

fn product_profile<'a>(
    expected_closure: &'a [ExpectedClosureEntry<'a>],
    observed_materials: &'a [ObservedRetainedMaterial<'a>],
) -> Wyr1aProductProfile<'a> {
    Wyr1aProductProfile {
        receipts: ProductReceiptIdentities {
            manifest: ExpectedObservedIdentity {
                expected: MANIFEST_RECEIPT_IDENTITY,
                observed: MANIFEST_RECEIPT_IDENTITY,
            },
            bootfs: ExpectedObservedIdentity {
                expected: BOOTFS_RECEIPT_IDENTITY,
                observed: BOOTFS_RECEIPT_IDENTITY,
            },
        },
        expected_closure,
        observed_materials,
    }
}

fn full_product_bytes() -> Vec<u8> {
    let expected = expected_product_closure();
    let observed = observed_product_materials();
    product_builder(false)
        .build_wyr1a_product(product_profile(&expected, &observed))
        .unwrap()
}

#[test]
fn immutable_empty_edge_golden_binds_structural_wire_bytes() {
    let mut builder = Builder::new(BOOT_IDENTITY);
    builder
        .add_role(role(
            RoleId::Registryd,
            "system/registryd",
            "minimum discovery",
            0x11,
        ))
        .unwrap();
    let encoded = builder.build_structural().unwrap();
    assert_eq!(encoded, decode_hex(EMPTY_EDGE_GOLDEN_HEX));
    let parsed = Manifest::parse_structural(&encoded, &BOOT_IDENTITY).unwrap();
    assert_eq!((parsed.role_count(), parsed.edge_count()), (1, 0));
    let expected = expected_product_closure();
    let observed = observed_product_materials();
    assert_eq!(
        parsed.validate_wyr1a_product(product_profile(&expected, &observed)),
        Err(ProductError::WrongRoleSet)
    );
}

#[test]
fn immutable_full_golden_is_product_valid_deterministic_and_zero_copy() {
    let expected = expected_product_closure();
    let observed = observed_product_materials();
    let profile = product_profile(&expected, &observed);
    let encoded = product_builder(false).build_wyr1a_product(profile).unwrap();
    assert_eq!(encoded, decode_hex(FULL_FIVE_ROLE_GOLDEN_HEX));
    assert_eq!(
        encoded,
        product_builder(true).build_wyr1a_product(profile).unwrap()
    );
    let parsed = Manifest::parse_wyr1a_product(&encoded, &BOOT_IDENTITY, profile).unwrap();
    let registryd = parsed.role(RoleId::Registryd).unwrap();
    assert_eq!(registryd.path(), "system/registryd");
    assert!(registryd.path().as_ptr() >= encoded.as_ptr());
    assert!(registryd.path().as_ptr() < encoded.as_ptr_range().end);
    let global_edge = parsed.edges().nth(1).unwrap();
    let role_edge = parsed
        .role(RoleId::Uart16550d)
        .unwrap()
        .edges()
        .next()
        .unwrap();
    assert_eq!(global_edge, role_edge);
    assert_eq!(role_edge.target_role(), Some(RoleId::Devmgr));
}

#[test]
fn product_acceptance_binds_external_manifest_and_bootfs_receipts() {
    let encoded = full_product_bytes();
    let expected = expected_product_closure();
    let observed = observed_product_materials();

    let mut manifest_mismatch = product_profile(&expected, &observed);
    manifest_mismatch.receipts.manifest.observed[0] ^= 1;
    assert_eq!(
        Manifest::parse_wyr1a_product(&encoded, &BOOT_IDENTITY, manifest_mismatch),
        Err(ProductError::ManifestReceiptIdentityMismatch)
    );

    let mut same_length_mutation = encoded.clone();
    same_length_mutation[HEADER_SIZE + 40] ^= 1;
    assert!(Manifest::parse_structural(&same_length_mutation, &BOOT_IDENTITY).is_ok());
    assert_eq!(
        Manifest::parse_wyr1a_product(&same_length_mutation, &BOOT_IDENTITY, manifest_mismatch),
        Err(ProductError::ManifestReceiptIdentityMismatch)
    );

    let mut manifest_zero = product_profile(&expected, &observed);
    manifest_zero.receipts.manifest.observed = [0; 32];
    assert_eq!(
        Manifest::parse_wyr1a_product(&encoded, &BOOT_IDENTITY, manifest_zero),
        Err(ProductError::ZeroManifestReceiptIdentity)
    );

    let mut bootfs_mismatch = product_profile(&expected, &observed);
    bootfs_mismatch.receipts.bootfs.observed[0] ^= 1;
    assert_eq!(
        Manifest::parse_wyr1a_product(&encoded, &BOOT_IDENTITY, bootfs_mismatch),
        Err(ProductError::BootfsReceiptIdentityMismatch)
    );

    let mut bootfs_zero = product_profile(&expected, &observed);
    bootfs_zero.receipts.bootfs.expected = [0; 32];
    assert_eq!(
        Manifest::parse_wyr1a_product(&encoded, &BOOT_IDENTITY, bootfs_zero),
        Err(ProductError::ZeroBootfsReceiptIdentity)
    );
}

#[test]
fn public_parser_names_separate_structural_from_product_acceptance() {
    let format_source = include_str!("../src/format.rs");
    let product_source = include_str!("../src/product.rs");
    assert!(format_source.contains("pub fn parse_structural("));
    assert!(!format_source.contains("pub fn parse("));
    assert!(product_source.contains("pub fn parse_wyr1a_product("));
}

#[test]
fn structural_flag_forms_are_valid_but_product_requires_both_bits() {
    let original = full_product_bytes();
    let expected = expected_product_closure();
    let observed = observed_product_materials();
    for flags in 0..=3 {
        let mut bytes = original.clone();
        write_u32(&mut bytes, HEADER_SIZE + 4, flags);
        let parsed = Manifest::parse_structural(&bytes, &BOOT_IDENTITY).unwrap();
        assert_eq!(
            parsed.role(RoleId::Registryd).unwrap().required(),
            flags & 1 != 0
        );
        assert_eq!(
            parsed.role(RoleId::Registryd).unwrap().requires_ready(),
            flags & 2 != 0
        );
        let result = parsed.validate_wyr1a_product(product_profile(&expected, &observed));
        assert_eq!(
            result,
            if flags == 3 {
                Ok(())
            } else {
                Err(ProductError::WrongRoleFlags)
            }
        );
    }
    let mut unknown = original;
    write_u32(&mut unknown, HEADER_SIZE + 4, 4);
    assert_eq!(
        Manifest::parse_structural(&unknown, &BOOT_IDENTITY),
        Err(ParseError::InvalidRoleFlags)
    );
}

#[test]
fn headers_truncation_counts_offsets_and_total_bounds_fail_closed() {
    let original = full_product_bytes();
    for end in [0, 1, HEADER_SIZE - 1, HEADER_SIZE, original.len() - 1] {
        assert!(Manifest::parse_structural(&original[..end], &BOOT_IDENTITY).is_err());
    }
    for (offset, expected) in [
        (0, ParseError::WrongMagic),
        (4, ParseError::UnsupportedVersion),
        (6, ParseError::UnsupportedVersion),
        (8, ParseError::WrongHeaderSize),
        (10, ParseError::WrongRoleRecordSize),
        (12, ParseError::WrongEdgeRecordSize),
        (14, ParseError::NonzeroHeaderReserved),
        (16, ParseError::NonzeroHeaderFlags),
        (32, ParseError::WrongSectionOffset),
        (36, ParseError::WrongSectionOffset),
        (40, ParseError::WrongSectionOffset),
        (44, ParseError::NonzeroHeaderReserved),
    ] {
        let mut malformed = original.clone();
        malformed[offset] ^= 1;
        assert_eq!(
            Manifest::parse_structural(&malformed, &BOOT_IDENTITY),
            Err(expected)
        );
    }
    for (offset, value, expected) in [
        (24, 0, ParseError::RoleCountOutOfRange),
        (24, 17, ParseError::RoleCountOutOfRange),
        (26, 65, ParseError::EdgeCountOutOfRange),
    ] {
        let mut malformed = original.clone();
        write_u16(&mut malformed, offset, value);
        assert_eq!(
            Manifest::parse_structural(&malformed, &BOOT_IDENTITY),
            Err(expected)
        );
    }
    let mut strings = original;
    write_u32(&mut strings, 28, 16 * 1024 + 1);
    assert_eq!(
        Manifest::parse_structural(&strings, &BOOT_IDENTITY),
        Err(ParseError::StringBytesOutOfRange)
    );
    assert_eq!(
        Manifest::parse_structural(&vec![0; MAX_TOTAL_BYTES + 1], &BOOT_IDENTITY),
        Err(ParseError::ManifestTooLarge)
    );
}

#[test]
fn role_fields_paths_utf8_reserved_and_identities_fail_closed() {
    let original = full_product_bytes();
    for (offset, expected) in [
        (HEADER_SIZE + 8, ParseError::UnsupportedResidency),
        (HEADER_SIZE + 12, ParseError::UnsupportedRestartPolicy),
        (HEADER_SIZE + 22, ParseError::NonzeroRoleReserved),
        (HEADER_SIZE + 30, ParseError::NonzeroRoleReserved),
        (HEADER_SIZE + 36, ParseError::NonzeroRoleReserved),
        (HEADER_SIZE + 72, ParseError::NonzeroRoleReserved),
        (HEADER_SIZE + 95, ParseError::NonzeroRoleReserved),
    ] {
        let mut malformed = original.clone();
        malformed[offset] ^= 1;
        assert_eq!(
            Manifest::parse_structural(&malformed, &BOOT_IDENTITY),
            Err(expected)
        );
    }
    let mut incompatible = original.clone();
    write_u16(&mut incompatible, HEADER_SIZE + 10, 2);
    assert_eq!(
        Manifest::parse_structural(&incompatible, &BOOT_IDENTITY),
        Err(ParseError::ActivationProfileMismatch)
    );
    let mut unknown_activation = original.clone();
    write_u16(&mut unknown_activation, HEADER_SIZE + 10, 4);
    assert_eq!(
        Manifest::parse_structural(&unknown_activation, &BOOT_IDENTITY),
        Err(ParseError::UnknownActivation)
    );
    let mut unknown_profile = original.clone();
    write_u16(&mut unknown_profile, HEADER_SIZE + 14, 2);
    assert_eq!(
        Manifest::parse_structural(&unknown_profile, &BOOT_IDENTITY),
        Err(ParseError::UnknownStartupProfile)
    );
    assert_eq!(
        Manifest::parse_structural(&original, &[0x43; 32]),
        Err(ParseError::BootGenerationIdentityMismatch)
    );
    let mut zero_boot = original.clone();
    zero_boot[48..80].fill(0);
    assert_eq!(
        Manifest::parse_structural(&zero_boot, &BOOT_IDENTITY),
        Err(ParseError::ZeroBootGenerationIdentity)
    );
    let mut zero_executable = original.clone();
    zero_executable[HEADER_SIZE + 40..HEADER_SIZE + 72].fill(0);
    assert_eq!(
        Manifest::parse_structural(&zero_executable, &BOOT_IDENTITY),
        Err(ParseError::ZeroExecutableIdentity)
    );
    let strings_offset = read_u32(&original, 40) as usize;
    let mut invalid_utf8 = original.clone();
    invalid_utf8[strings_offset] = 0xff;
    assert_eq!(
        Manifest::parse_structural(&invalid_utf8, &BOOT_IDENTITY),
        Err(ParseError::InvalidUtf8)
    );
    let mut gap = original;
    write_u32(&mut gap, HEADER_SIZE + 16, 1);
    assert_eq!(
        Manifest::parse_structural(&gap, &BOOT_IDENTITY),
        Err(ParseError::NoncanonicalStringLayout)
    );
    for path in ["system/../bad", "TRAILER!!!", "system\\bad"] {
        let mut builder = Builder::new(BOOT_IDENTITY);
        builder
            .add_role(role(RoleId::Registryd, path, "required", 1))
            .unwrap();
        assert_eq!(
            builder.build_structural(),
            Err(BuildError::InvalidManifest(ParseError::InvalidPath))
        );
    }
}

#[test]
fn canonical_role_edge_and_string_order_is_exact() {
    let original = full_product_bytes();
    let mut role_order = original.clone();
    write_u32(&mut role_order, HEADER_SIZE, RoleId::Devmgr as u32);
    write_u32(
        &mut role_order,
        HEADER_SIZE + ROLE_RECORD_SIZE,
        RoleId::Registryd as u32,
    );
    assert_eq!(
        Manifest::parse_structural(&role_order, &BOOT_IDENTITY),
        Err(ParseError::NoncanonicalRoleOrder)
    );
    let mut duplicate_paths = Builder::new(BOOT_IDENTITY);
    duplicate_paths
        .add_role(role(RoleId::Registryd, "system/same", "registry", 1))
        .unwrap();
    duplicate_paths
        .add_role(role(RoleId::Devmgr, "system/same", "devmgr", 2))
        .unwrap();
    assert_eq!(
        duplicate_paths.build_structural(),
        Err(BuildError::InvalidManifest(ParseError::DuplicateRolePath))
    );
    let mut duplicate_edges = Builder::new(BOOT_IDENTITY);
    duplicate_edges
        .add_role(role(RoleId::Registryd, "system/registryd", "required", 1))
        .unwrap();
    for _ in 0..2 {
        duplicate_edges
            .add_dependency(DependencySpec {
                owner: RoleId::Registryd,
                kind: DependencyKind::Config,
                target_role: None,
                target_path: Some("system/config/registryd"),
            })
            .unwrap();
    }
    assert_eq!(
        duplicate_edges.build_structural(),
        Err(BuildError::InvalidManifest(
            ParseError::NoncanonicalEdgeOrder
        ))
    );
    let mut ordered = Builder::new(BOOT_IDENTITY);
    ordered
        .add_role(role(RoleId::Registryd, "system/registryd", "required", 1))
        .unwrap();
    for (kind, path) in [
        (DependencyKind::Config, "system/config/a"),
        (DependencyKind::Runtime, "system/runtime/b"),
    ] {
        ordered
            .add_dependency(DependencySpec {
                owner: RoleId::Registryd,
                kind,
                target_role: None,
                target_path: Some(path),
            })
            .unwrap();
    }
    let mut out_of_order = ordered.build_structural().unwrap();
    let edges_offset = read_u32(&out_of_order, 36) as usize;
    write_u16(
        &mut out_of_order,
        edges_offset + 4,
        DependencyKind::Runtime as u16,
    );
    write_u16(
        &mut out_of_order,
        edges_offset + EDGE_RECORD_SIZE + 4,
        DependencyKind::Config as u16,
    );
    assert_eq!(
        Manifest::parse_structural(&out_of_order, &BOOT_IDENTITY),
        Err(ParseError::NoncanonicalEdgeOrder)
    );
}

#[test]
fn edge_shapes_ranges_missing_targets_cycles_and_reserved_fail_closed() {
    let original = full_product_bytes();
    let edges_offset = read_u32(&original, 36) as usize;
    let mut bad_range = original.clone();
    write_u16(&mut bad_range, HEADER_SIZE + 2 * ROLE_RECORD_SIZE + 32, 0);
    assert_eq!(
        Manifest::parse_structural(&bad_range, &BOOT_IDENTITY),
        Err(ParseError::InvalidRoleEdgeRange)
    );
    let mut bad_owner = original.clone();
    write_u32(&mut bad_owner, edges_offset, RoleId::Registryd as u32);
    assert_eq!(
        Manifest::parse_structural(&bad_owner, &BOOT_IDENTITY),
        Err(ParseError::WrongEdgeOwner)
    );
    let mut reserved = original;
    reserved[edges_offset + 18] = 1;
    assert_eq!(
        Manifest::parse_structural(&reserved, &BOOT_IDENTITY),
        Err(ParseError::NonzeroEdgeReserved)
    );
    let mut bad_flags = full_product_bytes();
    write_u16(&mut bad_flags, edges_offset + 6, 0);
    assert_eq!(
        Manifest::parse_structural(&bad_flags, &BOOT_IDENTITY),
        Err(ParseError::InvalidEdgeFlags)
    );
    let mut unknown_kind = full_product_bytes();
    write_u16(&mut unknown_kind, edges_offset + 4, 6);
    assert_eq!(
        Manifest::parse_structural(&unknown_kind, &BOOT_IDENTITY),
        Err(ParseError::UnknownDependencyKind)
    );
    let mut missing = Builder::new(BOOT_IDENTITY);
    missing
        .add_role(role(RoleId::Registryd, "system/registryd", "required", 1))
        .unwrap();
    missing
        .add_dependency(ready(RoleId::Registryd, RoleId::Devmgr))
        .unwrap();
    assert_eq!(
        missing.build_structural(),
        Err(BuildError::InvalidManifest(
            ParseError::MissingRoleDependency
        ))
    );
    let mut cycle = Builder::new(BOOT_IDENTITY);
    cycle
        .add_role(role(RoleId::Registryd, "system/registryd", "required", 1))
        .unwrap();
    cycle
        .add_role(role(RoleId::Devmgr, "system/devmgr", "required", 2))
        .unwrap();
    cycle
        .add_dependency(ready(RoleId::Registryd, RoleId::Devmgr))
        .unwrap();
    cycle
        .add_dependency(ready(RoleId::Devmgr, RoleId::Registryd))
        .unwrap();
    assert_eq!(
        cycle.build_structural(),
        Err(BuildError::InvalidManifest(ParseError::DependencyCycle))
    );
    let mut wrong_shape = Builder::new(BOOT_IDENTITY);
    wrong_shape
        .add_role(role(RoleId::Registryd, "system/registryd", "required", 1))
        .unwrap();
    wrong_shape
        .add_dependency(DependencySpec {
            owner: RoleId::Registryd,
            kind: DependencyKind::Config,
            target_role: Some(RoleId::Registryd),
            target_path: Some("system/config"),
        })
        .unwrap();
    assert_eq!(
        wrong_shape.build_structural(),
        Err(BuildError::InvalidManifest(ParseError::InvalidEdgeTarget))
    );

    let mut edge_utf8 = Builder::new(BOOT_IDENTITY);
    edge_utf8
        .add_role(role(RoleId::Registryd, "system/registryd", "required", 1))
        .unwrap();
    edge_utf8
        .add_dependency(DependencySpec {
            owner: RoleId::Registryd,
            kind: DependencyKind::Config,
            target_role: None,
            target_path: Some("system/config"),
        })
        .unwrap();
    let mut edge_utf8 = edge_utf8.build_structural().unwrap();
    let edge_offset = read_u32(&edge_utf8, 36) as usize;
    let string_offset = read_u32(&edge_utf8, 40) as usize;
    let target_offset = read_u32(&edge_utf8, edge_offset + 12) as usize;
    edge_utf8[string_offset + target_offset] = 0xff;
    assert_eq!(
        Manifest::parse_structural(&edge_utf8, &BOOT_IDENTITY),
        Err(ParseError::InvalidUtf8)
    );
}

#[test]
fn exact_product_roles_profiles_and_ready_graph_are_required() {
    let expected = expected_product_closure();
    let observed = observed_product_materials();
    let profile = product_profile(&expected, &observed);
    let mut wrong_activation = full_product_bytes();
    write_u16(
        &mut wrong_activation,
        HEADER_SIZE + 2 * ROLE_RECORD_SIZE + 10,
        Activation::ConsoleBound as u16,
    );
    let parsed = Manifest::parse_structural(&wrong_activation, &BOOT_IDENTITY).unwrap();
    assert_eq!(
        parsed.validate_wyr1a_product(profile),
        Err(ProductError::WrongRoleActivationProfile)
    );
    let mut missing_edge = Builder::new(BOOT_IDENTITY);
    for role in product_roles() {
        missing_edge.add_role(role).unwrap();
    }
    for edge in product_edges().into_iter().take(3) {
        missing_edge.add_dependency(edge).unwrap();
    }
    assert_eq!(
        missing_edge.build_wyr1a_product(profile),
        Err(BuildError::InvalidProduct(
            ProductError::WrongRoleReadyEdges
        ))
    );
    let mut early_unavailable = Builder::new(BOOT_IDENTITY);
    for role in product_roles() {
        early_unavailable.add_role(role).unwrap();
    }
    for edge in [
        ready(RoleId::Registryd, RoleId::Uart16550d),
        ready(RoleId::Uart16550d, RoleId::Devmgr),
        ready(RoleId::Consoled, RoleId::Uart16550d),
        ready(RoleId::Wyrmsh, RoleId::Consoled),
    ] {
        early_unavailable.add_dependency(edge).unwrap();
    }
    assert_eq!(
        early_unavailable.build_wyr1a_product(profile),
        Err(BuildError::InvalidProduct(
            ProductError::EarlyDependsOnUnavailableRole
        ))
    );
}

#[test]
fn retained_closure_is_exact_canonical_root_independent_and_identity_bound() {
    let mut builder = product_builder(false);
    builder
        .add_dependency(DependencySpec {
            owner: RoleId::Registryd,
            kind: DependencyKind::Config,
            target_role: None,
            target_path: Some("system/config/registryd"),
        })
        .unwrap();
    let mut expected = expected_product_closure();
    expected.insert(
        0,
        ExpectedClosureEntry {
            path: "system/config/registryd",
            identity: [0x77; 32],
            usage: ExpectedClosureUse::RoleDependency {
                owner: RoleId::Registryd,
                kind: ImmutableDependencyKind::Config,
            },
        },
    );
    let mut observed = observed_product_materials();
    observed.insert(0, observed_material("system/config/registryd", 0x77));
    assert!(
        builder
            .build_wyr1a_product(product_profile(&expected, &observed))
            .is_ok()
    );
    let mut missing_expected = expected.clone();
    missing_expected.remove(0);
    assert_eq!(
        builder.build_wyr1a_product(product_profile(&missing_expected, &observed)),
        Err(BuildError::InvalidProduct(
            ProductError::MissingRoleDependencyMaterial
        ))
    );

    let mut changed_dependency = observed.clone();
    changed_dependency[0].identity[0] ^= 1;
    assert_eq!(
        builder.build_wyr1a_product(product_profile(&expected, &changed_dependency)),
        Err(BuildError::InvalidProduct(
            ProductError::ObservedMaterialIdentityMismatch
        ))
    );

    let mut missing_init_dependency = observed.clone();
    missing_init_dependency.remove(5);
    assert_eq!(
        builder.build_wyr1a_product(product_profile(&expected, &missing_init_dependency)),
        Err(BuildError::InvalidProduct(
            ProductError::MissingObservedMaterial
        ))
    );

    let mut extra_init_dependency = observed.clone();
    extra_init_dependency.push(observed_material("system/zz-init-extra", 0x88));
    assert_eq!(
        builder.build_wyr1a_product(product_profile(&expected, &extra_init_dependency)),
        Err(BuildError::InvalidProduct(
            ProductError::UnexpectedObservedMaterial
        ))
    );

    let mut wrong_ownership = expected.clone();
    wrong_ownership[0].usage = ExpectedClosureUse::RoleDependency {
        owner: RoleId::Devmgr,
        kind: ImmutableDependencyKind::Config,
    };
    assert_eq!(
        builder.build_wyr1a_product(product_profile(&wrong_ownership, &observed)),
        Err(BuildError::InvalidProduct(
            ProductError::WrongClosureRoleDependency
        ))
    );

    let mut wrong_role_path = expected.clone();
    wrong_role_path[1].usage = ExpectedClosureUse::RoleExecutable {
        role: RoleId::Devmgr,
    };
    assert_eq!(
        builder.build_wyr1a_product(product_profile(&wrong_role_path, &observed)),
        Err(BuildError::InvalidProduct(ProductError::WrongClosurePath))
    );

    let mut wrong_role_identity = expected.clone();
    wrong_role_identity[2].identity[0] ^= 1;
    assert_eq!(
        builder.build_wyr1a_product(product_profile(&wrong_role_identity, &observed)),
        Err(BuildError::InvalidProduct(
            ProductError::RoleIdentityMismatch(RoleId::Devmgr)
        ))
    );

    let mut root_backed = observed.clone();
    root_backed[0].residence = MaterialResidence::PersistentRoot;
    assert_eq!(
        builder.build_wyr1a_product(product_profile(&expected, &root_backed)),
        Err(BuildError::InvalidProduct(ProductError::RootBackedMaterial))
    );
    let mut noncanonical = observed.clone();
    noncanonical.swap(0, 1);
    assert_eq!(
        builder.build_wyr1a_product(product_profile(&expected, &noncanonical)),
        Err(BuildError::InvalidProduct(
            ProductError::NoncanonicalObservedInventory
        ))
    );
    let mut duplicate_observed = observed.clone();
    let repeated_observed = duplicate_observed[0];
    duplicate_observed.insert(1, repeated_observed);
    assert_eq!(
        builder.build_wyr1a_product(product_profile(&expected, &duplicate_observed)),
        Err(BuildError::InvalidProduct(
            ProductError::NoncanonicalObservedInventory
        ))
    );
    let mut duplicate_expected = expected.clone();
    let repeated_expected = duplicate_expected[0];
    duplicate_expected.insert(1, repeated_expected);
    assert_eq!(
        builder.build_wyr1a_product(product_profile(&duplicate_expected, &observed)),
        Err(BuildError::InvalidProduct(
            ProductError::NoncanonicalExpectedClosure
        ))
    );
    let mut invalid_path = observed;
    invalid_path[0].path = "TRAILER!!!";
    assert_eq!(
        builder.build_wyr1a_product(product_profile(&expected, &invalid_path)),
        Err(BuildError::InvalidProduct(
            ProductError::InvalidObservedPath
        ))
    );
}

#[test]
fn inclusive_string_limits_and_exact_edge_limit_are_enforced() {
    let path_256 = "a".repeat(256);
    let justification_512 = "j".repeat(512);
    let mut exact = Builder::new(BOOT_IDENTITY);
    exact
        .add_role(role(RoleId::Registryd, &path_256, &justification_512, 1))
        .unwrap();
    assert!(exact.build_structural().is_ok());
    let path_257 = "a".repeat(257);
    let mut long = Builder::new(BOOT_IDENTITY);
    long.add_role(role(RoleId::Registryd, &path_257, "required", 1))
        .unwrap();
    assert_eq!(
        long.build_structural(),
        Err(BuildError::InvalidManifest(ParseError::InvalidPathLength))
    );
    let justification_513 = "j".repeat(513);
    let mut long_justification = Builder::new(BOOT_IDENTITY);
    long_justification
        .add_role(role(
            RoleId::Registryd,
            "system/registryd",
            &justification_513,
            1,
        ))
        .unwrap();
    assert_eq!(
        long_justification.build_structural(),
        Err(BuildError::InvalidManifest(
            ParseError::InvalidJustificationLength
        ))
    );
    let paths: Vec<String> = (0..=MAX_EDGES)
        .map(|i| format!("system/dependency/{i:02}"))
        .collect();
    let mut edges = Builder::new(BOOT_IDENTITY);
    edges
        .add_role(role(RoleId::Registryd, "system/registryd", "required", 1))
        .unwrap();
    for path in paths.iter().take(MAX_EDGES) {
        edges
            .add_dependency(DependencySpec {
                owner: RoleId::Registryd,
                kind: DependencyKind::Runtime,
                target_role: None,
                target_path: Some(path),
            })
            .unwrap();
    }
    assert!(edges.build_structural().is_ok());
    assert_eq!(
        edges.add_dependency(DependencySpec {
            owner: RoleId::Registryd,
            kind: DependencyKind::Runtime,
            target_role: None,
            target_path: Some(&paths[MAX_EDGES])
        }),
        Err(BuildError::EdgeLimit)
    );
}

#[test]
fn byte_mutations_never_panic() {
    let original = full_product_bytes();
    for index in 0..original.len() {
        let mut mutated = original.clone();
        mutated[index] ^= 0xa5;
        assert!(
            std::panic::catch_unwind(|| Manifest::parse_structural(&mutated, &BOOT_IDENTITY))
                .is_ok(),
            "mutation at {index} panicked"
        );
    }
}

fn decode_hex(encoded: &str) -> Vec<u8> {
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|p| (nibble(p[0]) << 4) | nibble(p[1]))
        .collect()
}
fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("invalid hex"),
    }
}
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
