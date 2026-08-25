//! Exact initial WYR1-A product-profile and retained-closure validation.

use wyrmroot_bootfs::path::ArchivePath;

use crate::{
    Activation, DependencyKind, MAX_PATH_BYTES, Manifest, ParseError, RoleId, StartupProfile,
};

const INIT_PATH: &str = "system/init";
const EXPECTED_ROLE_COUNT: usize = 5;
const EXPECTED_ROLE_READY_COUNT: usize = 4;

/// Where one resolver result would be loaded from during recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaterialResidence {
    /// Immutable selected-generation material retained independently of root.
    RetainedBootfs,
    /// Material that would require the future persistent root and is forbidden.
    PersistentRoot,
}

/// One canonical bootfs inventory result with its exact content identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedMaterial<'a> {
    pub path: &'a str,
    pub identity: [u8; 32],
    pub residence: MaterialResidence,
}

/// External identities and canonical retained inventory required to accept an
/// initial WYR1-A product manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Wyr1aProductProfile<'a> {
    pub init_identity: [u8; 32],
    pub materials: &'a [RetainedMaterial<'a>],
}

impl<'a> Manifest<'a> {
    /// Parses structural WRRM v1 and then applies the exact initial WYR1-A
    /// product role graph and retained-material closure.
    pub fn parse_wyr1a_product(
        bytes: &'a [u8],
        expected_boot_generation: &[u8; 32],
        profile: Wyr1aProductProfile<'_>,
    ) -> Result<Self, ProductError> {
        let manifest = Self::parse(bytes, expected_boot_generation).map_err(ProductError::Parse)?;
        manifest.validate_wyr1a_product(profile)?;
        Ok(manifest)
    }

    /// Validates the stricter initial WYR1-A role graph and exact retained
    /// closure after structural parsing has succeeded.
    pub fn validate_wyr1a_product(
        self,
        profile: Wyr1aProductProfile<'_>,
    ) -> Result<(), ProductError> {
        self.validate_product_roles()?;
        self.validate_product_role_edges()?;
        self.validate_retained_closure(profile)
    }

    fn validate_product_roles(self) -> Result<(), ProductError> {
        if self.role_count() != EXPECTED_ROLE_COUNT {
            return Err(ProductError::WrongRoleSet);
        }
        for (role, expected_id) in self.roles().zip([
            RoleId::Registryd,
            RoleId::Devmgr,
            RoleId::Uart16550d,
            RoleId::Consoled,
            RoleId::Wyrmsh,
        ]) {
            if role.id() != expected_id {
                return Err(ProductError::WrongRoleSet);
            }
            if !role.required() || !role.requires_ready() {
                return Err(ProductError::WrongRoleFlags);
            }
            let expected_profile = match expected_id {
                RoleId::Registryd | RoleId::Devmgr => {
                    (Activation::Early, StartupProfile::EarlyBootStub)
                }
                RoleId::Uart16550d => (Activation::DeviceBound, StartupProfile::Retained),
                RoleId::Consoled | RoleId::Wyrmsh => {
                    (Activation::ConsoleBound, StartupProfile::Retained)
                }
            };
            if (role.activation(), role.startup_profile()) != expected_profile {
                return Err(ProductError::WrongRoleActivationProfile);
            }
        }
        Ok(())
    }

    fn validate_product_role_edges(self) -> Result<(), ProductError> {
        let mut observed = 0u8;
        let mut count = 0usize;
        for edge in self.edges() {
            if edge.kind() != DependencyKind::RoleReady {
                continue;
            }
            count += 1;
            let target = edge
                .target_role()
                .ok_or(ProductError::WrongRoleReadyEdges)?;
            let owner = edge.owner();
            if self
                .role(owner)
                .is_some_and(|role| role.activation() == Activation::Early)
                && self
                    .role(target)
                    .is_some_and(|role| role.activation() != Activation::Early)
            {
                return Err(ProductError::EarlyDependsOnUnavailableRole);
            }
            let bit = match (owner, target) {
                (RoleId::Devmgr, RoleId::Registryd) => 1 << 0,
                (RoleId::Uart16550d, RoleId::Devmgr) => 1 << 1,
                (RoleId::Consoled, RoleId::Uart16550d) => 1 << 2,
                (RoleId::Wyrmsh, RoleId::Consoled) => 1 << 3,
                _ => return Err(ProductError::WrongRoleReadyEdges),
            };
            if observed & bit != 0 {
                return Err(ProductError::WrongRoleReadyEdges);
            }
            observed |= bit;
        }
        if count != EXPECTED_ROLE_READY_COUNT || observed != 0b1111 {
            return Err(ProductError::WrongRoleReadyEdges);
        }
        Ok(())
    }

    fn validate_retained_closure(
        self,
        profile: Wyr1aProductProfile<'_>,
    ) -> Result<(), ProductError> {
        if is_zero_identity(&profile.init_identity) {
            return Err(ProductError::ZeroInitIdentity);
        }
        let mut previous_path = None;
        for material in profile.materials {
            let path = material.path.as_bytes();
            if path.len() > MAX_PATH_BYTES || ArchivePath::new(path).is_err() {
                return Err(ProductError::InvalidInventoryPath);
            }
            if previous_path.is_some_and(|previous: &[u8]| path <= previous) {
                return Err(ProductError::NoncanonicalInventory);
            }
            previous_path = Some(path);
            if material.residence != MaterialResidence::RetainedBootfs {
                return Err(ProductError::RootBackedMaterial);
            }
            if is_zero_identity(&material.identity) {
                return Err(ProductError::ZeroMaterialIdentity);
            }
            if !self.declares_material_path(material.path) {
                return Err(ProductError::UndeclaredRetainedMaterial);
            }
        }

        let init = find_material(profile.materials, INIT_PATH).ok_or(ProductError::MissingInit)?;
        if init.identity != profile.init_identity {
            return Err(ProductError::InitIdentityMismatch);
        }
        for role in self.roles() {
            let material = find_material(profile.materials, role.path())
                .ok_or(ProductError::MissingRoleMaterial(role.id()))?;
            if &material.identity != role.executable_identity() {
                return Err(ProductError::RoleIdentityMismatch(role.id()));
            }
        }
        for edge in self.edges() {
            if let Some(path) = edge.target_path() {
                find_material(profile.materials, path)
                    .ok_or(ProductError::MissingDependencyMaterial)?;
            }
        }
        Ok(())
    }

    fn declares_material_path(self, candidate: &str) -> bool {
        candidate == INIT_PATH
            || self.roles().any(|role| role.path() == candidate)
            || self
                .edges()
                .any(|edge| edge.target_path() == Some(candidate))
    }
}

/// Fail-closed initial WYR1-A product/closure validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductError {
    Parse(ParseError),
    WrongRoleSet,
    WrongRoleFlags,
    WrongRoleActivationProfile,
    WrongRoleReadyEdges,
    EarlyDependsOnUnavailableRole,
    ZeroInitIdentity,
    InvalidInventoryPath,
    NoncanonicalInventory,
    RootBackedMaterial,
    ZeroMaterialIdentity,
    UndeclaredRetainedMaterial,
    MissingInit,
    InitIdentityMismatch,
    MissingRoleMaterial(RoleId),
    RoleIdentityMismatch(RoleId),
    MissingDependencyMaterial,
}

fn find_material<'a>(
    materials: &'a [RetainedMaterial<'a>],
    path: &str,
) -> Option<&'a RetainedMaterial<'a>> {
    materials.iter().find(|material| material.path == path)
}

fn is_zero_identity(identity: &[u8; 32]) -> bool {
    identity.iter().all(|byte| *byte == 0)
}
