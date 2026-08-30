#[path = "../src/artifacts.rs"]
mod artifacts;
#[path = "../src/config.rs"]
mod config;

use artifacts::{
    ArtifactError, ArtifactInputs, BOOT_DEVICE_TABLE_PATH, BOOTFS_PATH, BOOTSTRAP_PATH, KERNEL_PATH,
};
use config::{ConfigError, LoaderConfig, MAX_CONFIG_BYTES, Profile};

#[test]
fn canonical_paths_are_fixed_and_ordered() {
    assert_eq!(KERNEL_PATH, "/EFI/Wyrmroot/deepwyrm.elf");
    assert_eq!(BOOTSTRAP_PATH, "/EFI/Wyrmroot/bootstrap.elf");
    assert_eq!(BOOTFS_PATH, "/EFI/Wyrmroot/bootfs.img");
    assert_eq!(BOOT_DEVICE_TABLE_PATH, "/EFI/Wyrmroot/BDEVICE.BIN");
}

#[test]
fn artifact_validation_reports_each_missing_input() {
    let cases = [
        (
            ArtifactInputs {
                kernel: None,
                bootstrap: Some(b"bootstrap"),
                bootfs: Some(b"bootfs"),
            },
            ArtifactError::MissingKernel,
        ),
        (
            ArtifactInputs {
                kernel: Some(b"kernel"),
                bootstrap: None,
                bootfs: Some(b"bootfs"),
            },
            ArtifactError::MissingBootstrap,
        ),
        (
            ArtifactInputs {
                kernel: Some(b"kernel"),
                bootstrap: Some(b"bootstrap"),
                bootfs: None,
            },
            ArtifactError::MissingBootfs,
        ),
    ];

    for (inputs, expected) in cases {
        assert_eq!(inputs.validate(), Err(expected));
    }
}

#[test]
fn zero_length_artifacts_fail_closed() {
    assert_eq!(
        (ArtifactInputs {
            kernel: Some(b""),
            bootstrap: Some(b"bootstrap"),
            bootfs: Some(b"bootfs"),
        })
        .validate(),
        Err(ArtifactError::EmptyKernel)
    );
}

#[test]
fn config_accepts_only_default_profile() {
    assert_eq!(
        LoaderConfig::parse(b"# Wyrmroot loader\r\nprofile=default\n"),
        Ok(LoaderConfig {
            profile: Profile::Default
        })
    );
}

#[test]
fn config_rejects_malformed_duplicate_unknown_and_override_values() {
    assert_eq!(
        LoaderConfig::parse(b"profile"),
        Err(ConfigError::MalformedLine)
    );
    assert_eq!(
        LoaderConfig::parse(b"profile=default\nprofile=default"),
        Err(ConfigError::DuplicateKey)
    );
    assert_eq!(
        LoaderConfig::parse(b"root=/tmp"),
        Err(ConfigError::UnknownKey)
    );
    assert_eq!(
        LoaderConfig::parse(b"profile=/EFI/Other"),
        Err(ConfigError::UnsupportedProfile)
    );
}

#[test]
fn config_rejects_non_utf8_and_oversized_input() {
    assert_eq!(LoaderConfig::parse(&[0xff]), Err(ConfigError::InvalidUtf8));
    let oversized = [b'x'; MAX_CONFIG_BYTES + 1];
    assert_eq!(LoaderConfig::parse(&oversized), Err(ConfigError::TooLarge));
}
