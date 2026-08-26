//! Deterministic host-side WRRM v1 construction.

extern crate alloc;

use alloc::vec::Vec;

use crate::{
    Activation, DependencyKind, EDGE_RECORD_SIZE, HEADER_SIZE, MAX_EDGES, MAX_ROLES,
    MAX_STRING_BYTES, MAX_TOTAL_BYTES, Manifest, ParseError, ProductError, ROLE_RECORD_SIZE,
    RoleId, StartupProfile, Wyr1aProductProfile,
};

/// Caller-provided role declaration. Residency and restart policy are fixed by
/// WRRM v1 and are not caller-selectable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoleSpec<'a> {
    pub id: RoleId,
    pub required: bool,
    pub requires_ready: bool,
    pub activation: Activation,
    pub startup_profile: StartupProfile,
    pub path: &'a str,
    pub justification: &'a str,
    pub executable_identity: [u8; 32],
}

/// Caller-provided required dependency edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DependencySpec<'a> {
    pub owner: RoleId,
    pub kind: DependencyKind,
    pub target_role: Option<RoleId>,
    pub target_path: Option<&'a str>,
}

/// Deterministic WRRM v1 builder. Caller insertion order is discarded.
#[derive(Debug)]
pub struct Builder<'a> {
    boot_generation_identity: [u8; 32],
    roles: Vec<RoleSpec<'a>>,
    edges: Vec<DependencySpec<'a>>,
}

impl<'a> Builder<'a> {
    pub const fn new(boot_generation_identity: [u8; 32]) -> Self {
        Self {
            boot_generation_identity,
            roles: Vec::new(),
            edges: Vec::new(),
        }
    }

    pub fn add_role(&mut self, role: RoleSpec<'a>) -> Result<(), BuildError> {
        if self.roles.len() == MAX_ROLES {
            return Err(BuildError::RoleLimit);
        }
        self.roles
            .try_reserve(1)
            .map_err(|_| BuildError::AllocationFailure)?;
        self.roles.push(role);
        Ok(())
    }

    pub fn add_dependency(&mut self, edge: DependencySpec<'a>) -> Result<(), BuildError> {
        if self.edges.len() == MAX_EDGES {
            return Err(BuildError::EdgeLimit);
        }
        self.edges
            .try_reserve(1)
            .map_err(|_| BuildError::AllocationFailure)?;
        self.edges.push(edge);
        Ok(())
    }

    /// Encodes structurally valid WRRM v1 bytes without claiming that they
    /// satisfy either exact WYR1 product profile or retained closure.
    /// Production image construction must use [`Self::build_wyr1a_product`].
    pub fn build_structural(&self) -> Result<Vec<u8>, BuildError> {
        let mut roles = Vec::new();
        roles
            .try_reserve_exact(self.roles.len())
            .map_err(|_| BuildError::AllocationFailure)?;
        roles.extend_from_slice(&self.roles);
        roles.sort_unstable_by_key(|role| role.id);

        let mut edges = Vec::new();
        edges
            .try_reserve_exact(self.edges.len())
            .map_err(|_| BuildError::AllocationFailure)?;
        edges.extend_from_slice(&self.edges);
        edges.sort_unstable_by(|left, right| edge_key(left).cmp(&edge_key(right)));

        let mut string_bytes = 0usize;
        for role in &roles {
            string_bytes = checked_add(string_bytes, role.path.len())?;
            string_bytes = checked_add(string_bytes, role.justification.len())?;
        }
        for edge in &edges {
            if let Some(path) = edge.target_path {
                string_bytes = checked_add(string_bytes, path.len())?;
            }
        }
        if string_bytes > MAX_STRING_BYTES {
            return Err(BuildError::ManifestTooLarge);
        }

        let edges_offset = checked_add(HEADER_SIZE, checked_mul(roles.len(), ROLE_RECORD_SIZE)?)?;
        let strings_offset =
            checked_add(edges_offset, checked_mul(edges.len(), EDGE_RECORD_SIZE)?)?;
        let total_size = checked_add(strings_offset, string_bytes)?;
        if total_size > MAX_TOTAL_BYTES {
            return Err(BuildError::ManifestTooLarge);
        }

        let mut output = Vec::new();
        output
            .try_reserve_exact(total_size)
            .map_err(|_| BuildError::AllocationFailure)?;
        output.resize(total_size, 0);
        output[..4].copy_from_slice(b"WRRM");
        write_u16(&mut output, 4, 1);
        write_u16(&mut output, 6, 0);
        write_u16(&mut output, 8, HEADER_SIZE as u16);
        write_u16(&mut output, 10, ROLE_RECORD_SIZE as u16);
        write_u16(&mut output, 12, EDGE_RECORD_SIZE as u16);
        write_u32(&mut output, 20, checked_u32(total_size)?);
        write_u16(&mut output, 24, checked_u16(roles.len())?);
        write_u16(&mut output, 26, checked_u16(edges.len())?);
        write_u32(&mut output, 28, checked_u32(string_bytes)?);
        write_u32(&mut output, 32, HEADER_SIZE as u32);
        write_u32(&mut output, 36, checked_u32(edges_offset)?);
        write_u32(&mut output, 40, checked_u32(strings_offset)?);
        output[48..80].copy_from_slice(&self.boot_generation_identity);

        let mut string_cursor = 0usize;
        let mut first_edge = 0usize;
        for (index, role) in roles.iter().enumerate() {
            let record_offset = HEADER_SIZE + index * ROLE_RECORD_SIZE;
            write_u32(&mut output, record_offset, role.id as u32);
            let flags = u32::from(role.required) | (u32::from(role.requires_ready) << 1);
            write_u32(&mut output, record_offset + 4, flags);
            write_u16(&mut output, record_offset + 8, 1);
            write_u16(&mut output, record_offset + 10, role.activation as u16);
            write_u16(&mut output, record_offset + 12, 1);
            write_u16(&mut output, record_offset + 14, role.startup_profile as u16);
            write_u32(&mut output, record_offset + 16, checked_u32(string_cursor)?);
            write_u16(
                &mut output,
                record_offset + 20,
                checked_u16(role.path.len())?,
            );
            copy_string(
                &mut output,
                strings_offset,
                &mut string_cursor,
                role.path.as_bytes(),
            );
            write_u32(&mut output, record_offset + 24, checked_u32(string_cursor)?);
            write_u16(
                &mut output,
                record_offset + 28,
                checked_u16(role.justification.len())?,
            );
            copy_string(
                &mut output,
                strings_offset,
                &mut string_cursor,
                role.justification.as_bytes(),
            );
            let role_edge_count = edges.iter().filter(|edge| edge.owner == role.id).count();
            write_u16(&mut output, record_offset + 32, checked_u16(first_edge)?);
            write_u16(
                &mut output,
                record_offset + 34,
                checked_u16(role_edge_count)?,
            );
            first_edge = checked_add(first_edge, role_edge_count)?;
            output[record_offset + 40..record_offset + 72]
                .copy_from_slice(&role.executable_identity);
        }

        for (index, edge) in edges.iter().enumerate() {
            let record_offset = edges_offset + index * EDGE_RECORD_SIZE;
            write_u32(&mut output, record_offset, edge.owner as u32);
            write_u16(&mut output, record_offset + 4, edge.kind as u16);
            write_u16(&mut output, record_offset + 6, 1);
            write_u32(
                &mut output,
                record_offset + 8,
                edge.target_role.map_or(0, |role| role as u32),
            );
            write_u32(&mut output, record_offset + 12, checked_u32(string_cursor)?);
            let path = edge.target_path.unwrap_or("");
            write_u16(&mut output, record_offset + 16, checked_u16(path.len())?);
            copy_string(
                &mut output,
                strings_offset,
                &mut string_cursor,
                path.as_bytes(),
            );
        }
        debug_assert_eq!(string_cursor, string_bytes);

        Manifest::parse_structural(&output, &self.boot_generation_identity)
            .map_err(BuildError::InvalidManifest)?;
        Ok(output)
    }

    /// Encodes only after the exact initial product graph and canonical
    /// retained-material closure validate successfully.
    pub fn build_wyr1a_product(
        &self,
        profile: Wyr1aProductProfile<'_>,
    ) -> Result<Vec<u8>, BuildError> {
        let output = self.build_structural()?;
        let manifest = Manifest::parse_structural(&output, &self.boot_generation_identity)
            .map_err(BuildError::InvalidManifest)?;
        manifest
            .validate_wyr1a_product(profile)
            .map_err(BuildError::InvalidProduct)?;
        Ok(output)
    }

    pub fn build_wyr1b_product(
        &self,
        profile: crate::Wyr1bProductProfile<'_>,
    ) -> Result<Vec<u8>, BuildError> {
        let output = self.build_structural()?;
        let manifest = Manifest::parse_structural(&output, &self.boot_generation_identity)
            .map_err(BuildError::InvalidManifest)?;
        manifest
            .validate_wyr1b_product(profile)
            .map_err(BuildError::InvalidProduct)?;
        Ok(output)
    }
}

/// Why deterministic host construction failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildError {
    RoleLimit,
    EdgeLimit,
    ManifestTooLarge,
    AllocationFailure,
    InvalidManifest(ParseError),
    InvalidProduct(ProductError),
}

fn edge_key<'a>(
    edge: &'a DependencySpec<'a>,
) -> (RoleId, DependencyKind, Option<RoleId>, &'a [u8]) {
    (
        edge.owner,
        edge.kind,
        edge.target_role,
        edge.target_path.unwrap_or("").as_bytes(),
    )
}

fn copy_string(output: &mut [u8], base: usize, cursor: &mut usize, value: &[u8]) {
    let start = base + *cursor;
    output[start..start + value.len()].copy_from_slice(value);
    *cursor += value.len();
}

fn checked_add(left: usize, right: usize) -> Result<usize, BuildError> {
    left.checked_add(right).ok_or(BuildError::ManifestTooLarge)
}

fn checked_mul(left: usize, right: usize) -> Result<usize, BuildError> {
    left.checked_mul(right).ok_or(BuildError::ManifestTooLarge)
}

fn checked_u16(value: usize) -> Result<u16, BuildError> {
    u16::try_from(value).map_err(|_| BuildError::ManifestTooLarge)
}

fn checked_u32(value: usize) -> Result<u32, BuildError> {
    u32::try_from(value).map_err(|_| BuildError::ManifestTooLarge)
}

fn write_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
