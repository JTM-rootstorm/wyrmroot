//! Allocation-free WRRM v1 parsing and canonical-form validation.

use core::cmp::Ordering;

use wyrmroot_bootfs::path::ArchivePath;

/// Canonical bootfs entry carrying the WYR1-A RRC manifest.
pub const MANIFEST_PATH: &str = "system/bootstrap/rrc-a-v1";
/// Fixed WRRM v1 header size.
pub const HEADER_SIZE: usize = 80;
/// Fixed WRRM v1 role-record size.
pub const ROLE_RECORD_SIZE: usize = 96;
/// Fixed WRRM v1 dependency-edge size.
pub const EDGE_RECORD_SIZE: usize = 32;
/// Maximum number of role records accepted by WRRM v1.
pub const MAX_ROLES: usize = 16;
/// Maximum number of dependency edges accepted by WRRM v1.
pub const MAX_EDGES: usize = 64;
/// Maximum bytes in one canonical bootfs path.
pub const MAX_PATH_BYTES: usize = 256;
/// Maximum bytes in one RRC-A justification.
pub const MAX_JUSTIFICATION_BYTES: usize = 512;
/// Maximum aggregate bytes in the raw string table.
pub const MAX_STRING_BYTES: usize = 16 * 1024;
/// Maximum exact WRRM v1 byte length.
pub const MAX_TOTAL_BYTES: usize = 64 * 1024;

const MAGIC: [u8; 4] = *b"WRRM";
const MAJOR: u16 = 1;
const MINOR: u16 = 0;
const ROLE_FLAG_REQUIRED: u32 = 1 << 0;
const ROLE_FLAG_REQUIRES_READY: u32 = 1 << 1;
const ROLE_FLAGS_MASK: u32 = ROLE_FLAG_REQUIRED | ROLE_FLAG_REQUIRES_READY;
const EDGE_FLAG_REQUIRED: u16 = 1;
const RESIDENCY_RRC_A: u16 = 1;
const RESTART_POLICY_FINITE_WYR1: u16 = 1;

/// Coordinator-owned role identifiers fixed for WYR1-A.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum RoleId {
    Registryd = 1,
    Devmgr = 2,
    Uart16550d = 3,
    Consoled = 4,
    Wyrmsh = 5,
}

impl RoleId {
    fn from_wire(value: u32) -> Result<Self, ParseError> {
        match value {
            1 => Ok(Self::Registryd),
            2 => Ok(Self::Devmgr),
            3 => Ok(Self::Uart16550d),
            4 => Ok(Self::Consoled),
            5 => Ok(Self::Wyrmsh),
            _ => Err(ParseError::UnknownRoleId),
        }
    }
}

/// WYR1 activation class encoded by one role record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Activation {
    Early = 1,
    DeviceBound = 2,
    ConsoleBound = 3,
}

impl Activation {
    fn from_wire(value: u16) -> Result<Self, ParseError> {
        match value {
            1 => Ok(Self::Early),
            2 => Ok(Self::DeviceBound),
            3 => Ok(Self::ConsoleBound),
            _ => Err(ParseError::UnknownActivation),
        }
    }
}

/// Child startup profile assigned by the reached WYR1-A contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum StartupProfile {
    Retained = 0,
    EarlyBootStub = 1,
}

impl StartupProfile {
    fn from_wire(value: u16) -> Result<Self, ParseError> {
        match value {
            0 => Ok(Self::Retained),
            1 => Ok(Self::EarlyBootStub),
            _ => Err(ParseError::UnknownStartupProfile),
        }
    }
}

/// Dependency kind encoded by one WRRM edge.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum DependencyKind {
    Executable = 1,
    Config = 2,
    Runtime = 3,
    Firmware = 4,
    RoleReady = 5,
}

impl DependencyKind {
    fn from_wire(value: u16) -> Result<Self, ParseError> {
        match value {
            1 => Ok(Self::Executable),
            2 => Ok(Self::Config),
            3 => Ok(Self::Runtime),
            4 => Ok(Self::Firmware),
            5 => Ok(Self::RoleReady),
            _ => Err(ParseError::UnknownDependencyKind),
        }
    }
}

/// One validated, borrowed WRRM v1 manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Manifest<'a> {
    bytes: &'a [u8],
    role_count: usize,
    edge_count: usize,
    edges_offset: usize,
    strings_offset: usize,
}

impl<'a> Manifest<'a> {
    /// Parses one exact WRRM v1 byte stream and binds it to the selected boot
    /// generation identity supplied by the integration request.
    ///
    /// SHA-256 values are treated as opaque exact 32-byte identities. This
    /// function compares them but does not hash artifact bytes.
    pub fn parse(bytes: &'a [u8], expected_boot_generation: &[u8; 32]) -> Result<Self, ParseError> {
        if bytes.len() > MAX_TOTAL_BYTES {
            return Err(ParseError::ManifestTooLarge);
        }
        if bytes.len() < HEADER_SIZE {
            return Err(ParseError::TruncatedHeader);
        }
        if bytes[..4] != MAGIC {
            return Err(ParseError::WrongMagic);
        }
        if read_u16(bytes, 4) != MAJOR || read_u16(bytes, 6) != MINOR {
            return Err(ParseError::UnsupportedVersion);
        }
        if usize::from(read_u16(bytes, 8)) != HEADER_SIZE {
            return Err(ParseError::WrongHeaderSize);
        }
        if usize::from(read_u16(bytes, 10)) != ROLE_RECORD_SIZE {
            return Err(ParseError::WrongRoleRecordSize);
        }
        if usize::from(read_u16(bytes, 12)) != EDGE_RECORD_SIZE {
            return Err(ParseError::WrongEdgeRecordSize);
        }
        if read_u16(bytes, 14) != 0 || read_u32(bytes, 44) != 0 {
            return Err(ParseError::NonzeroHeaderReserved);
        }
        if read_u32(bytes, 16) != 0 {
            return Err(ParseError::NonzeroHeaderFlags);
        }
        let total_size = to_usize(read_u32(bytes, 20))?;
        if total_size != bytes.len() {
            return Err(ParseError::WrongTotalSize);
        }
        let role_count = usize::from(read_u16(bytes, 24));
        if !(1..=MAX_ROLES).contains(&role_count) {
            return Err(ParseError::RoleCountOutOfRange);
        }
        let edge_count = usize::from(read_u16(bytes, 26));
        if edge_count > MAX_EDGES {
            return Err(ParseError::EdgeCountOutOfRange);
        }
        let string_bytes = to_usize(read_u32(bytes, 28))?;
        if string_bytes > MAX_STRING_BYTES {
            return Err(ParseError::StringBytesOutOfRange);
        }

        let expected_edges_offset = HEADER_SIZE
            .checked_add(
                role_count
                    .checked_mul(ROLE_RECORD_SIZE)
                    .ok_or(ParseError::SizeOverflow)?,
            )
            .ok_or(ParseError::SizeOverflow)?;
        let expected_strings_offset = expected_edges_offset
            .checked_add(
                edge_count
                    .checked_mul(EDGE_RECORD_SIZE)
                    .ok_or(ParseError::SizeOverflow)?,
            )
            .ok_or(ParseError::SizeOverflow)?;
        let expected_total = expected_strings_offset
            .checked_add(string_bytes)
            .ok_or(ParseError::SizeOverflow)?;
        if to_usize(read_u32(bytes, 32))? != HEADER_SIZE
            || to_usize(read_u32(bytes, 36))? != expected_edges_offset
            || to_usize(read_u32(bytes, 40))? != expected_strings_offset
        {
            return Err(ParseError::WrongSectionOffset);
        }
        if expected_total != bytes.len() {
            return Err(ParseError::WrongTotalSize);
        }

        let encoded_boot_generation = array_32(bytes, 48);
        if is_zero_identity(encoded_boot_generation) {
            return Err(ParseError::ZeroBootGenerationIdentity);
        }
        if is_zero_identity(expected_boot_generation)
            || encoded_boot_generation != expected_boot_generation
        {
            return Err(ParseError::BootGenerationIdentityMismatch);
        }

        let manifest = Self {
            bytes,
            role_count,
            edge_count,
            edges_offset: expected_edges_offset,
            strings_offset: expected_strings_offset,
        };
        manifest.validate_records(string_bytes)?;
        Ok(manifest)
    }

    /// Exact selected-boot-generation identity encoded by this manifest.
    pub fn boot_generation_identity(self) -> &'a [u8; 32] {
        array_32(self.bytes, 48)
    }

    /// Number of validated role records.
    pub const fn role_count(self) -> usize {
        self.role_count
    }

    /// Number of validated dependency edges.
    pub const fn edge_count(self) -> usize {
        self.edge_count
    }

    /// Iterates roles in strict canonical role-ID order.
    pub const fn roles(self) -> Roles<'a> {
        Roles {
            manifest: self,
            index: 0,
        }
    }

    /// Iterates dependency edges in canonical tuple order.
    pub const fn edges(self) -> DependencyEdges<'a> {
        DependencyEdges {
            manifest: self,
            index: 0,
            end: self.edge_count,
        }
    }

    /// Finds one fixed WYR1-A role.
    pub fn role(self, role_id: RoleId) -> Option<Role<'a>> {
        self.roles().find(|role| role.id() == role_id)
    }

    fn validate_records(self, string_bytes: usize) -> Result<(), ParseError> {
        let mut string_cursor = 0usize;
        let mut expected_first_edge = 0usize;
        let mut previous_role_id = None;

        for role_index in 0..self.role_count {
            let record = self.role_bytes(role_index);
            let role_id = RoleId::from_wire(read_u32(record, 0))?;
            if previous_role_id.is_some_and(|previous| role_id <= previous) {
                return Err(ParseError::NoncanonicalRoleOrder);
            }
            previous_role_id = Some(role_id);

            let flags = read_u32(record, 4);
            if flags & !ROLE_FLAGS_MASK != 0 {
                return Err(ParseError::InvalidRoleFlags);
            }
            if read_u16(record, 8) != RESIDENCY_RRC_A {
                return Err(ParseError::UnsupportedResidency);
            }
            let activation = Activation::from_wire(read_u16(record, 10))?;
            if read_u16(record, 12) != RESTART_POLICY_FINITE_WYR1 {
                return Err(ParseError::UnsupportedRestartPolicy);
            }
            let profile = StartupProfile::from_wire(read_u16(record, 14))?;
            validate_activation_profile(activation, profile)?;
            if read_u16(record, 22) != 0
                || read_u16(record, 30) != 0
                || read_u32(record, 36) != 0
                || record[72..96].iter().any(|byte| *byte != 0)
            {
                return Err(ParseError::NonzeroRoleReserved);
            }
            if is_zero_identity(array_32(record, 40)) {
                return Err(ParseError::ZeroExecutableIdentity);
            }

            let path_offset = to_usize(read_u32(record, 16))?;
            let path_len = usize::from(read_u16(record, 20));
            if !(1..=MAX_PATH_BYTES).contains(&path_len) {
                return Err(ParseError::InvalidPathLength);
            }
            if path_offset != string_cursor {
                return Err(ParseError::NoncanonicalStringLayout);
            }
            let path = self.string(path_offset, path_len, string_bytes)?;
            core::str::from_utf8(path).map_err(|_| ParseError::InvalidUtf8)?;
            ArchivePath::new(path).map_err(|_| ParseError::InvalidPath)?;
            string_cursor = string_cursor
                .checked_add(path_len)
                .ok_or(ParseError::SizeOverflow)?;

            let justification_offset = to_usize(read_u32(record, 24))?;
            let justification_len = usize::from(read_u16(record, 28));
            if !(1..=MAX_JUSTIFICATION_BYTES).contains(&justification_len) {
                return Err(ParseError::InvalidJustificationLength);
            }
            if justification_offset != string_cursor {
                return Err(ParseError::NoncanonicalStringLayout);
            }
            let justification =
                self.string(justification_offset, justification_len, string_bytes)?;
            core::str::from_utf8(justification).map_err(|_| ParseError::InvalidUtf8)?;
            string_cursor = string_cursor
                .checked_add(justification_len)
                .ok_or(ParseError::SizeOverflow)?;

            let first_edge = usize::from(read_u16(record, 32));
            let role_edge_count = usize::from(read_u16(record, 34));
            let edge_end = first_edge
                .checked_add(role_edge_count)
                .ok_or(ParseError::SizeOverflow)?;
            if first_edge != expected_first_edge || edge_end > self.edge_count {
                return Err(ParseError::InvalidRoleEdgeRange);
            }
            expected_first_edge = edge_end;
        }
        if expected_first_edge != self.edge_count {
            return Err(ParseError::InvalidRoleEdgeRange);
        }

        for left in 0..self.role_count {
            for right in left + 1..self.role_count {
                if self.role_at(left).path().as_bytes() == self.role_at(right).path().as_bytes() {
                    return Err(ParseError::DuplicateRolePath);
                }
            }
        }

        let mut previous_edge = None;
        for edge_index in 0..self.edge_count {
            let record = self.edge_bytes(edge_index);
            if record[18..32].iter().any(|byte| *byte != 0) {
                return Err(ParseError::NonzeroEdgeReserved);
            }
            let owner = RoleId::from_wire(read_u32(record, 0))?;
            let expected_owner = self.owner_for_edge(edge_index)?;
            if owner != expected_owner {
                return Err(ParseError::WrongEdgeOwner);
            }
            let kind = DependencyKind::from_wire(read_u16(record, 4))?;
            if read_u16(record, 6) != EDGE_FLAG_REQUIRED {
                return Err(ParseError::InvalidEdgeFlags);
            }
            let target_role_raw = read_u32(record, 8);
            let target_path_offset = to_usize(read_u32(record, 12))?;
            let target_path_len = usize::from(read_u16(record, 16));
            if target_path_offset != string_cursor {
                return Err(ParseError::NoncanonicalStringLayout);
            }

            let (target_role, target_path) = if kind == DependencyKind::RoleReady {
                if target_role_raw == 0 || target_path_len != 0 {
                    return Err(ParseError::InvalidEdgeTarget);
                }
                let target = RoleId::from_wire(target_role_raw)?;
                if self.role(target).is_none() {
                    return Err(ParseError::MissingRoleDependency);
                }
                (Some(target), &[][..])
            } else {
                if target_role_raw != 0 || !(1..=MAX_PATH_BYTES).contains(&target_path_len) {
                    return Err(ParseError::InvalidEdgeTarget);
                }
                let target_path = self.string(target_path_offset, target_path_len, string_bytes)?;
                core::str::from_utf8(target_path).map_err(|_| ParseError::InvalidUtf8)?;
                ArchivePath::new(target_path).map_err(|_| ParseError::InvalidPath)?;
                string_cursor = string_cursor
                    .checked_add(target_path_len)
                    .ok_or(ParseError::SizeOverflow)?;
                (None, target_path)
            };

            let key = EdgeKey {
                owner,
                kind,
                target_role,
                target_path,
            };
            if previous_edge
                .is_some_and(|previous: EdgeKey<'_>| key.cmp(&previous) != Ordering::Greater)
            {
                return Err(ParseError::NoncanonicalEdgeOrder);
            }
            previous_edge = Some(key);
        }
        if string_cursor != string_bytes {
            return Err(ParseError::NoncanonicalStringLayout);
        }
        self.validate_acyclic_role_dependencies()
    }

    fn validate_acyclic_role_dependencies(self) -> Result<(), ParseError> {
        for start in self.roles() {
            let start_bit = 1u32 << (start.id() as u32 - 1);
            let mut visited = start_bit;
            let mut frontier = 0u32;
            for edge in start.edges() {
                if let Some(target) = edge.target_role() {
                    frontier |= 1u32 << (target as u32 - 1);
                }
            }
            while frontier != 0 {
                let bit = frontier.trailing_zeros();
                frontier &= !(1u32 << bit);
                let role_bit = 1u32 << bit;
                if role_bit == start_bit {
                    return Err(ParseError::DependencyCycle);
                }
                if visited & role_bit != 0 {
                    continue;
                }
                visited |= role_bit;
                let role_id = RoleId::from_wire(bit + 1)?;
                let role = self
                    .role(role_id)
                    .ok_or(ParseError::MissingRoleDependency)?;
                for edge in role.edges() {
                    if let Some(target) = edge.target_role() {
                        let target_bit = 1u32 << (target as u32 - 1);
                        if target_bit == start_bit {
                            return Err(ParseError::DependencyCycle);
                        }
                        if visited & target_bit == 0 {
                            frontier |= target_bit;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn owner_for_edge(self, edge_index: usize) -> Result<RoleId, ParseError> {
        for role in self.roles() {
            let range = role.edge_range();
            if range.contains(&edge_index) {
                return Ok(role.id());
            }
        }
        Err(ParseError::InvalidRoleEdgeRange)
    }

    fn role_at(self, index: usize) -> Role<'a> {
        Role {
            manifest: self,
            index,
        }
    }

    fn edge_at(self, index: usize) -> DependencyEdge<'a> {
        DependencyEdge {
            manifest: self,
            index,
        }
    }

    fn role_bytes(self, index: usize) -> &'a [u8] {
        let start = HEADER_SIZE + index * ROLE_RECORD_SIZE;
        &self.bytes[start..start + ROLE_RECORD_SIZE]
    }

    fn edge_bytes(self, index: usize) -> &'a [u8] {
        let start = self.edges_offset + index * EDGE_RECORD_SIZE;
        &self.bytes[start..start + EDGE_RECORD_SIZE]
    }

    fn string(
        self,
        relative_offset: usize,
        len: usize,
        string_bytes: usize,
    ) -> Result<&'a [u8], ParseError> {
        let end = relative_offset
            .checked_add(len)
            .ok_or(ParseError::SizeOverflow)?;
        if end > string_bytes {
            return Err(ParseError::StringOutOfRange);
        }
        Ok(&self.bytes[self.strings_offset + relative_offset..self.strings_offset + end])
    }
}

/// Iterator over validated role records.
#[derive(Clone, Copy, Debug)]
pub struct Roles<'a> {
    manifest: Manifest<'a>,
    index: usize,
}

impl<'a> Iterator for Roles<'a> {
    type Item = Role<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.manifest.role_count {
            return None;
        }
        let role = self.manifest.role_at(self.index);
        self.index += 1;
        Some(role)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.manifest.role_count - self.index;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Roles<'_> {}

/// One validated role record borrowing its path, justification, and identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Role<'a> {
    manifest: Manifest<'a>,
    index: usize,
}

impl<'a> Role<'a> {
    fn bytes(self) -> &'a [u8] {
        self.manifest.role_bytes(self.index)
    }

    pub fn id(self) -> RoleId {
        RoleId::from_wire(read_u32(self.bytes(), 0)).expect("validated WRRM role ID")
    }

    pub fn required(self) -> bool {
        read_u32(self.bytes(), 4) & ROLE_FLAG_REQUIRED != 0
    }

    pub fn requires_ready(self) -> bool {
        read_u32(self.bytes(), 4) & ROLE_FLAG_REQUIRES_READY != 0
    }

    pub fn activation(self) -> Activation {
        Activation::from_wire(read_u16(self.bytes(), 10)).expect("validated WRRM activation")
    }

    pub fn startup_profile(self) -> StartupProfile {
        StartupProfile::from_wire(read_u16(self.bytes(), 14))
            .expect("validated WRRM startup profile")
    }

    pub fn path(self) -> &'a str {
        let record = self.bytes();
        let offset = read_u32(record, 16) as usize;
        let len = usize::from(read_u16(record, 20));
        core::str::from_utf8(
            &self.manifest.bytes[self.manifest.strings_offset + offset
                ..self.manifest.strings_offset + offset + len],
        )
        .expect("validated WRRM role path")
    }

    pub fn justification(self) -> &'a str {
        let record = self.bytes();
        let offset = read_u32(record, 24) as usize;
        let len = usize::from(read_u16(record, 28));
        core::str::from_utf8(
            &self.manifest.bytes[self.manifest.strings_offset + offset
                ..self.manifest.strings_offset + offset + len],
        )
        .expect("validated WRRM justification")
    }

    pub fn executable_identity(self) -> &'a [u8; 32] {
        array_32(self.bytes(), 40)
    }

    pub fn edges(self) -> DependencyEdges<'a> {
        let range = self.edge_range();
        DependencyEdges {
            manifest: self.manifest,
            index: range.start,
            end: range.end,
        }
    }

    fn edge_range(self) -> core::ops::Range<usize> {
        let record = self.bytes();
        let start = usize::from(read_u16(record, 32));
        start..start + usize::from(read_u16(record, 34))
    }
}

/// Iterator over validated dependency edges.
#[derive(Clone, Copy, Debug)]
pub struct DependencyEdges<'a> {
    manifest: Manifest<'a>,
    index: usize,
    end: usize,
}

impl<'a> Iterator for DependencyEdges<'a> {
    type Item = DependencyEdge<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.end {
            return None;
        }
        let edge = self.manifest.edge_at(self.index);
        self.index += 1;
        Some(edge)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.end - self.index;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for DependencyEdges<'_> {}

/// One validated dependency edge borrowing any target path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DependencyEdge<'a> {
    manifest: Manifest<'a>,
    index: usize,
}

impl<'a> DependencyEdge<'a> {
    fn bytes(self) -> &'a [u8] {
        self.manifest.edge_bytes(self.index)
    }

    pub fn owner(self) -> RoleId {
        RoleId::from_wire(read_u32(self.bytes(), 0)).expect("validated WRRM edge owner")
    }

    pub fn kind(self) -> DependencyKind {
        DependencyKind::from_wire(read_u16(self.bytes(), 4))
            .expect("validated WRRM dependency kind")
    }

    pub const fn required(self) -> bool {
        true
    }

    pub fn target_role(self) -> Option<RoleId> {
        let raw = read_u32(self.bytes(), 8);
        (raw != 0).then(|| RoleId::from_wire(raw).expect("validated WRRM target role"))
    }

    pub fn target_path(self) -> Option<&'a str> {
        let record = self.bytes();
        let len = usize::from(read_u16(record, 16));
        if len == 0 {
            return None;
        }
        let offset = read_u32(record, 12) as usize;
        Some(
            core::str::from_utf8(
                &self.manifest.bytes[self.manifest.strings_offset + offset
                    ..self.manifest.strings_offset + offset + len],
            )
            .expect("validated WRRM dependency path"),
        )
    }
}

#[derive(Clone, Copy)]
struct EdgeKey<'a> {
    owner: RoleId,
    kind: DependencyKind,
    target_role: Option<RoleId>,
    target_path: &'a [u8],
}

impl Ord for EdgeKey<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.owner, self.kind, self.target_role, self.target_path).cmp(&(
            other.owner,
            other.kind,
            other.target_role,
            other.target_path,
        ))
    }
}

impl PartialOrd for EdgeKey<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for EdgeKey<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for EdgeKey<'_> {}

/// Fail-closed reason a WRRM byte stream was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    TruncatedHeader,
    ManifestTooLarge,
    WrongMagic,
    UnsupportedVersion,
    WrongHeaderSize,
    WrongRoleRecordSize,
    WrongEdgeRecordSize,
    NonzeroHeaderReserved,
    NonzeroHeaderFlags,
    WrongTotalSize,
    RoleCountOutOfRange,
    EdgeCountOutOfRange,
    StringBytesOutOfRange,
    SizeOverflow,
    WrongSectionOffset,
    ZeroBootGenerationIdentity,
    BootGenerationIdentityMismatch,
    UnknownRoleId,
    NoncanonicalRoleOrder,
    InvalidRoleFlags,
    UnsupportedResidency,
    UnknownActivation,
    UnsupportedRestartPolicy,
    UnknownStartupProfile,
    ActivationProfileMismatch,
    InvalidPathLength,
    InvalidJustificationLength,
    NonzeroRoleReserved,
    ZeroExecutableIdentity,
    InvalidRoleEdgeRange,
    DuplicateRolePath,
    StringOutOfRange,
    InvalidUtf8,
    InvalidPath,
    NoncanonicalStringLayout,
    NonzeroEdgeReserved,
    WrongEdgeOwner,
    UnknownDependencyKind,
    InvalidEdgeFlags,
    InvalidEdgeTarget,
    MissingRoleDependency,
    NoncanonicalEdgeOrder,
    DependencyCycle,
}

fn validate_activation_profile(
    activation: Activation,
    profile: StartupProfile,
) -> Result<(), ParseError> {
    if matches!(
        (activation, profile),
        (Activation::Early, StartupProfile::EarlyBootStub)
            | (
                Activation::DeviceBound | Activation::ConsoleBound,
                StartupProfile::Retained
            )
    ) {
        Ok(())
    } else {
        Err(ParseError::ActivationProfileMismatch)
    }
}

fn is_zero_identity(identity: &[u8; 32]) -> bool {
    identity.iter().all(|byte| *byte == 0)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn array_32(bytes: &[u8], offset: usize) -> &[u8; 32] {
    bytes[offset..offset + 32]
        .try_into()
        .expect("validated fixed-size WRRM field")
}

fn to_usize(value: u32) -> Result<usize, ParseError> {
    usize::try_from(value).map_err(|_| ParseError::SizeOverflow)
}
