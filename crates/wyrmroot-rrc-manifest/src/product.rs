//! Exact initial WYR1-A product-profile and retained-closure validation.

use core::cmp::Ordering;

use wyrmroot_bootfs::path::ArchivePath;

use crate::{
    Activation, DependencyKind, MAX_PATH_BYTES, Manifest, ParseError, RoleId, StartupProfile,
};

const INIT_PATH: &str = "system/init";
const EXPECTED_ROLE_COUNT: usize = 5;
const EXPECTED_ROLE_READY_COUNT: usize = 4;

/// Independently obtained expected and observed SHA-256 identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedObservedIdentity {
    pub expected: [u8; 32],
    pub observed: [u8; 32],
}

/// External receipt identities binding the WRRM bytes and containing bootfs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductReceiptIdentities {
    pub manifest: ExpectedObservedIdentity,
    pub bootfs: ExpectedObservedIdentity,
}

/// Immutable non-role dependency kinds. `ROLE_READY` is intentionally absent.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ImmutableDependencyKind {
    Executable,
    Config,
    Runtime,
    Firmware,
}

impl ImmutableDependencyKind {
    fn from_manifest(kind: DependencyKind) -> Option<Self> {
        match kind {
            DependencyKind::Executable => Some(Self::Executable),
            DependencyKind::Config => Some(Self::Config),
            DependencyKind::Runtime => Some(Self::Runtime),
            DependencyKind::Firmware => Some(Self::Firmware),
            DependencyKind::RoleReady => None,
        }
    }
}

/// Why one expected immutable path belongs in the retained closure.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ExpectedClosureUse {
    /// The permanent supervisor executable itself.
    SystemInit,
    /// A dependency used only by init and therefore absent from role edges.
    InitDependency { kind: ImmutableDependencyKind },
    /// The exact executable named by one manifest role record.
    RoleExecutable { role: RoleId },
    /// One manifest-declared non-role dependency edge.
    RoleDependency {
        owner: RoleId,
        kind: ImmutableDependencyKind,
    },
}

/// One canonical expected closure declaration supplied by integration policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedClosureEntry<'a> {
    pub path: &'a str,
    pub identity: [u8; 32],
    pub usage: ExpectedClosureUse,
}

/// Where one observed resolver result would be loaded from during recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaterialResidence {
    /// Immutable selected-generation material retained independently of root.
    RetainedBootfs,
    /// Material that would require the future persistent root and is forbidden.
    PersistentRoot,
}

/// One observed canonical bootfs inventory result and content identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedRetainedMaterial<'a> {
    pub path: &'a str,
    pub identity: [u8; 32],
    pub residence: MaterialResidence,
}

/// External receipts, expected closure, and observed retained inventory needed
/// to accept one initial WYR1-A product manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Wyr1aProductProfile<'a> {
    pub receipts: ProductReceiptIdentities,
    pub expected_closure: &'a [ExpectedClosureEntry<'a>],
    pub observed_materials: &'a [ObservedRetainedMaterial<'a>],
}

/// WYR1-B retains the same RRC closure and receipts while assigning registryd
/// its reached resident bootstrap profile.
pub type Wyr1bProductProfile<'a> = Wyr1aProductProfile<'a>;

/// WYR1-C1 retains the WYR1-B registry profile and closure while assigning
/// devmgr its distinct resident device-coordinator startup profile.
pub type Wyr1cProductProfile<'a> = Wyr1aProductProfile<'a>;

/// Reset card R1 reuses WYR1-C1's role graph without change.
///
/// Its product early-activates registryd as the resident `BootstrapRegistry`
/// and devmgr as the resident `DeviceCoordinator`, and leaves uart16550d,
/// consoled and wyrmsh `Retained` — which is exactly C1's graph. Reset plan
/// §8.1 excludes UART recovery, console pressure and shell parsing from this
/// card, so those three staying non-launchable is the requirement rather than
/// an omission, and reusing C1's validator is what enforces it: a manifest that
/// granted wyrmsh its production profile would be refused here rather than
/// merely unused.
///
/// This is an alias, not a second copy of the rules. The card gets a named
/// entry point so its intent is recorded and a future divergence has somewhere
/// to live, while the graph it validates stays literally the same code.
pub type R1ProductProfile<'a> = Wyr1cProductProfile<'a>;

/// WYR1-E selected-product inputs. The production shell identity is supplied
/// independently of WRRM so admission cannot accept a consistently substituted
/// retained-stub identity in the manifest and closure inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Wyr1eProductProfile<'a> {
    pub base: Wyr1aProductProfile<'a>,
    pub production_wyrmsh_identity: [u8; 32],
}

impl<'a> Manifest<'a> {
    /// Parses structural WRRM v1 and then applies the exact initial WYR1-A
    /// product role graph, external receipts, and retained-material closure.
    pub fn parse_wyr1a_product(
        bytes: &'a [u8],
        expected_boot_generation: &[u8; 32],
        profile: Wyr1aProductProfile<'_>,
    ) -> Result<Self, ProductError> {
        let manifest = Self::parse_structural(bytes, expected_boot_generation)
            .map_err(ProductError::StructuralParse)?;
        manifest.validate_wyr1a_product(profile)?;
        Ok(manifest)
    }

    /// Validates the stricter initial WYR1-A graph and its independently bound
    /// receipts and closure after structural parsing succeeds.
    pub fn validate_wyr1a_product(
        self,
        profile: Wyr1aProductProfile<'_>,
    ) -> Result<(), ProductError> {
        validate_receipts(profile.receipts)?;
        self.validate_product_roles(
            StartupProfile::EarlyBootStub,
            StartupProfile::EarlyBootStub,
            StartupProfile::Retained,
        )?;
        self.validate_product_role_edges()?;
        self.validate_expected_closure(profile.expected_closure)?;
        validate_observed_materials(profile.expected_closure, profile.observed_materials)
    }

    pub fn parse_wyr1b_product(
        bytes: &'a [u8],
        expected_boot_generation: &[u8; 32],
        profile: Wyr1bProductProfile<'_>,
    ) -> Result<Self, ProductError> {
        let manifest = Self::parse_structural(bytes, expected_boot_generation)
            .map_err(ProductError::StructuralParse)?;
        manifest.validate_wyr1b_product(profile)?;
        Ok(manifest)
    }

    pub fn validate_wyr1b_product(
        self,
        profile: Wyr1bProductProfile<'_>,
    ) -> Result<(), ProductError> {
        validate_receipts(profile.receipts)?;
        self.validate_product_roles(
            StartupProfile::BootstrapRegistry,
            StartupProfile::EarlyBootStub,
            StartupProfile::Retained,
        )?;
        self.validate_product_role_edges()?;
        self.validate_expected_closure(profile.expected_closure)?;
        validate_observed_materials(profile.expected_closure, profile.observed_materials)
    }

    /// Parses structural WRRM v1 and then applies the exact WYR1-C1 product
    /// role graph, external receipts, and retained-material closure.
    pub fn parse_wyr1c_product(
        bytes: &'a [u8],
        expected_boot_generation: &[u8; 32],
        profile: Wyr1cProductProfile<'_>,
    ) -> Result<Self, ProductError> {
        let manifest = Self::parse_structural(bytes, expected_boot_generation)
            .map_err(ProductError::StructuralParse)?;
        manifest.validate_wyr1c_product(profile)?;
        Ok(manifest)
    }

    /// Validates the exact WYR1-C1 graph. Registryd retains WYR1-B's
    /// BootstrapRegistry profile, devmgr gets the new DeviceCoordinator
    /// profile, and every role edge and retained closure entry stays exact.
    pub fn validate_wyr1c_product(
        self,
        profile: Wyr1cProductProfile<'_>,
    ) -> Result<(), ProductError> {
        validate_receipts(profile.receipts)?;
        self.validate_product_roles(
            StartupProfile::BootstrapRegistry,
            StartupProfile::DeviceCoordinator,
            StartupProfile::Retained,
        )?;
        self.validate_product_role_edges()?;
        self.validate_expected_closure(profile.expected_closure)?;
        validate_observed_materials(profile.expected_closure, profile.observed_materials)
    }

    /// Parses structural WRRM v1 and then applies reset card R1's product role
    /// graph, which is WYR1-C1's.
    pub fn parse_r1_product(
        bytes: &'a [u8],
        expected_boot_generation: &[u8; 32],
        profile: R1ProductProfile<'_>,
    ) -> Result<Self, ProductError> {
        Self::parse_wyr1c_product(bytes, expected_boot_generation, profile)
    }

    /// Validates reset card R1's product graph. Delegates to the C1 validator
    /// deliberately: R1 requires the same resident registry and device
    /// coordinator and the same three non-launchable roles, and a divergence
    /// should be a deliberate edit here rather than a drift between two copies.
    pub fn validate_r1_product(self, profile: R1ProductProfile<'_>) -> Result<(), ProductError> {
        self.validate_wyr1c_product(profile)
    }

    /// Parses structural WRRM v1 and applies the exact WYR1-E selected-product
    /// graph, retained closure, receipts, and independent production shell
    /// identity.
    pub fn parse_wyr1e_product(
        bytes: &'a [u8],
        expected_boot_generation: &[u8; 32],
        profile: Wyr1eProductProfile<'_>,
    ) -> Result<Self, ProductError> {
        let manifest = Self::parse_structural(bytes, expected_boot_generation)
            .map_err(ProductError::StructuralParse)?;
        manifest.validate_wyr1e_product(profile)?;
        Ok(manifest)
    }

    /// Validates the new WYR1-E product without weakening the historical
    /// WYR1-A/B/C requirement that role 5 use the Retained profile.
    pub fn validate_wyr1e_product(
        self,
        profile: Wyr1eProductProfile<'_>,
    ) -> Result<(), ProductError> {
        if is_zero_identity(&profile.production_wyrmsh_identity) {
            return Err(ProductError::ZeroProductionWyrmshIdentity);
        }
        validate_receipts(profile.base.receipts)?;
        self.validate_product_roles(
            StartupProfile::BootstrapRegistry,
            StartupProfile::DeviceCoordinator,
            StartupProfile::Wyrmsh,
        )?;
        let wyrmsh = self
            .role(RoleId::Wyrmsh)
            .ok_or(ProductError::WrongRoleSet)?;
        if wyrmsh.executable_identity() != &profile.production_wyrmsh_identity {
            return Err(ProductError::ProductionWyrmshIdentityMismatch);
        }
        self.validate_product_role_edges()?;
        self.validate_expected_closure(profile.base.expected_closure)?;
        validate_observed_materials(
            profile.base.expected_closure,
            profile.base.observed_materials,
        )
    }

    fn validate_product_roles(
        self,
        registry_profile: StartupProfile,
        devmgr_profile: StartupProfile,
        wyrmsh_profile: StartupProfile,
    ) -> Result<(), ProductError> {
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
                RoleId::Registryd => (Activation::Early, registry_profile),
                RoleId::Devmgr => (Activation::Early, devmgr_profile),
                RoleId::Uart16550d => (Activation::DeviceBound, StartupProfile::Retained),
                RoleId::Consoled => (Activation::ConsoleBound, StartupProfile::Retained),
                RoleId::Wyrmsh => (Activation::ConsoleBound, wyrmsh_profile),
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

    fn validate_expected_closure(
        self,
        expected: &[ExpectedClosureEntry<'_>],
    ) -> Result<(), ProductError> {
        let mut previous: Option<(&[u8], ExpectedClosureUse, [u8; 32])> = None;
        let mut init_count = 0usize;
        for entry in expected {
            let path = entry.path.as_bytes();
            validate_closure_path(path).map_err(|_| ProductError::InvalidExpectedPath)?;
            if is_zero_identity(&entry.identity) {
                return Err(ProductError::ZeroExpectedMaterialIdentity);
            }
            if let Some((previous_path, previous_usage, previous_identity)) = previous {
                match path.cmp(previous_path) {
                    Ordering::Less => return Err(ProductError::NoncanonicalExpectedClosure),
                    Ordering::Equal if entry.usage <= previous_usage => {
                        return Err(ProductError::NoncanonicalExpectedClosure);
                    }
                    Ordering::Equal if entry.identity != previous_identity => {
                        return Err(ProductError::ConflictingExpectedIdentity);
                    }
                    Ordering::Equal | Ordering::Greater => {}
                }
            }
            previous = Some((path, entry.usage, entry.identity));

            match entry.usage {
                ExpectedClosureUse::SystemInit => {
                    if entry.path != INIT_PATH {
                        return Err(ProductError::WrongSystemInitPath);
                    }
                    init_count += 1;
                }
                ExpectedClosureUse::InitDependency { .. } => {
                    if entry.path == INIT_PATH {
                        return Err(ProductError::WrongInitDependencyPath);
                    }
                }
                ExpectedClosureUse::RoleExecutable { role } => {
                    let manifest_role = self
                        .role(role)
                        .ok_or(ProductError::WrongClosureRoleOwnership)?;
                    if manifest_role.path() != entry.path {
                        return Err(ProductError::WrongClosurePath);
                    }
                    if manifest_role.executable_identity() != &entry.identity {
                        return Err(ProductError::RoleIdentityMismatch(role));
                    }
                }
                ExpectedClosureUse::RoleDependency { owner, kind } => {
                    if !self.edges().any(|edge| {
                        edge.owner() == owner
                            && edge.target_path() == Some(entry.path)
                            && ImmutableDependencyKind::from_manifest(edge.kind()) == Some(kind)
                    }) {
                        return Err(ProductError::WrongClosureRoleDependency);
                    }
                }
            }
        }
        if init_count != 1 {
            return Err(ProductError::MissingOrDuplicateSystemInit);
        }
        for role in self.roles() {
            if !expected.iter().any(|entry| {
                entry.path == role.path()
                    && entry.usage == (ExpectedClosureUse::RoleExecutable { role: role.id() })
            }) {
                return Err(ProductError::MissingRoleMaterial(role.id()));
            }
        }
        for edge in self.edges() {
            if let Some(path) = edge.target_path() {
                let kind = ImmutableDependencyKind::from_manifest(edge.kind())
                    .ok_or(ProductError::WrongClosureRoleDependency)?;
                if !expected.iter().any(|entry| {
                    entry.path == path
                        && entry.usage
                            == (ExpectedClosureUse::RoleDependency {
                                owner: edge.owner(),
                                kind,
                            })
                }) {
                    return Err(ProductError::MissingRoleDependencyMaterial);
                }
            }
        }
        Ok(())
    }
}

/// Fail-closed initial WYR1-A product/closure validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductError {
    StructuralParse(ParseError),
    ZeroManifestReceiptIdentity,
    ManifestReceiptIdentityMismatch,
    ZeroBootfsReceiptIdentity,
    BootfsReceiptIdentityMismatch,
    ZeroProductionWyrmshIdentity,
    ProductionWyrmshIdentityMismatch,
    WrongRoleSet,
    WrongRoleFlags,
    WrongRoleActivationProfile,
    WrongRoleReadyEdges,
    EarlyDependsOnUnavailableRole,
    InvalidExpectedPath,
    NoncanonicalExpectedClosure,
    ZeroExpectedMaterialIdentity,
    ConflictingExpectedIdentity,
    WrongSystemInitPath,
    WrongInitDependencyPath,
    MissingOrDuplicateSystemInit,
    WrongClosureRoleOwnership,
    WrongClosurePath,
    WrongClosureRoleDependency,
    MissingRoleMaterial(RoleId),
    RoleIdentityMismatch(RoleId),
    MissingRoleDependencyMaterial,
    InvalidObservedPath,
    NoncanonicalObservedInventory,
    RootBackedMaterial,
    ZeroObservedMaterialIdentity,
    UnexpectedObservedMaterial,
    MissingObservedMaterial,
    ObservedMaterialIdentityMismatch,
}

fn validate_receipts(receipts: ProductReceiptIdentities) -> Result<(), ProductError> {
    if is_zero_identity(&receipts.manifest.expected)
        || is_zero_identity(&receipts.manifest.observed)
    {
        return Err(ProductError::ZeroManifestReceiptIdentity);
    }
    if receipts.manifest.expected != receipts.manifest.observed {
        return Err(ProductError::ManifestReceiptIdentityMismatch);
    }
    if is_zero_identity(&receipts.bootfs.expected) || is_zero_identity(&receipts.bootfs.observed) {
        return Err(ProductError::ZeroBootfsReceiptIdentity);
    }
    if receipts.bootfs.expected != receipts.bootfs.observed {
        return Err(ProductError::BootfsReceiptIdentityMismatch);
    }
    Ok(())
}

fn validate_observed_materials(
    expected: &[ExpectedClosureEntry<'_>],
    observed: &[ObservedRetainedMaterial<'_>],
) -> Result<(), ProductError> {
    let mut previous_path = None;
    for material in observed {
        let path = material.path.as_bytes();
        validate_closure_path(path).map_err(|_| ProductError::InvalidObservedPath)?;
        if previous_path.is_some_and(|previous: &[u8]| path <= previous) {
            return Err(ProductError::NoncanonicalObservedInventory);
        }
        previous_path = Some(path);
        if material.residence != MaterialResidence::RetainedBootfs {
            return Err(ProductError::RootBackedMaterial);
        }
        if is_zero_identity(&material.identity) {
            return Err(ProductError::ZeroObservedMaterialIdentity);
        }
        if !expected.iter().any(|entry| entry.path == material.path) {
            return Err(ProductError::UnexpectedObservedMaterial);
        }
    }
    for entry in expected {
        let material = observed
            .iter()
            .find(|material| material.path == entry.path)
            .ok_or(ProductError::MissingObservedMaterial)?;
        if material.identity != entry.identity {
            return Err(ProductError::ObservedMaterialIdentityMismatch);
        }
    }
    Ok(())
}

fn validate_closure_path(path: &[u8]) -> Result<(), ()> {
    if path.len() > MAX_PATH_BYTES || ArchivePath::new(path).is_err() {
        Err(())
    } else {
        Ok(())
    }
}

fn is_zero_identity(identity: &[u8; 32]) -> bool {
    identity.iter().all(|byte| *byte == 0)
}
