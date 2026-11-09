//! The workspace's Cargo feature graph, as Cargo itself reads it.
//!
//! Host tests that hold "this product feature implies, or never implies, that
//! one" ask `cargo metadata` for every workspace package's declared features
//! rather than splitting manifest text, so they see exactly the graph a build
//! resolves. Only same-package implications are followed: `dep:` entries and
//! `package/feature` entries name other packages and are not part of a
//! package's own closure.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::process::{Command, Stdio};

use crate::deep_layout::{JsonParser, JsonValue};

/// Every workspace package's `[features]` table.
pub(crate) struct WorkspaceFeatures {
    packages: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

impl WorkspaceFeatures {
    /// Reads the workspace's own manifests with `cargo metadata --no-deps`,
    /// which resolves no dependency and touches no network or lockfile entry.
    pub(crate) fn load() -> Self {
        let repository = crate::tasks::repository_root().expect("resolve Wyrmroot root");
        let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let output = Command::new(cargo)
            .args([
                "metadata",
                "--format-version",
                "1",
                "--no-deps",
                "--offline",
                "--locked",
            ])
            .current_dir(repository)
            .stdin(Stdio::null())
            .output()
            .expect("run cargo metadata");
        assert!(
            output.status.success(),
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).expect("cargo metadata is UTF-8");
        let root = JsonParser::new(&text)
            .parse()
            .expect("parse cargo metadata");
        let mut packages = BTreeMap::new();
        for package in root
            .object_field("packages")
            .and_then(|packages| packages.as_array("packages"))
            .expect("metadata packages")
        {
            let name = package
                .object_field("name")
                .and_then(|name| name.as_string("package name"))
                .expect("package name");
            let JsonValue::Object(table) = package.object_field("features").expect("features")
            else {
                panic!("{name}'s features are not an object");
            };
            let features = table
                .iter()
                .map(|(feature, enables)| {
                    let enables = enables
                        .as_array("feature list")
                        .expect("feature list")
                        .iter()
                        .map(|entry| entry.as_string("feature entry").unwrap().to_owned())
                        .collect();
                    (feature.clone(), enables)
                })
                .collect();
            packages.insert(name.to_owned(), features);
        }
        Self { packages }
    }

    /// The features `package` declares.
    pub(crate) fn declared(&self, package: &str) -> BTreeSet<&str> {
        self.table(package).keys().map(String::as_str).collect()
    }

    /// Every feature of `package` that building it with the comma-separated
    /// `features` turns on, the requested ones included.
    pub(crate) fn closure(&self, package: &str, features: &str) -> BTreeSet<String> {
        let table = self.table(package);
        let mut enabled = BTreeSet::new();
        let mut pending = features.split(',').map(str::to_owned).collect::<Vec<_>>();
        while let Some(feature) = pending.pop() {
            let Some(enables) = table.get(&feature) else {
                panic!("{package} declares no feature {feature}");
            };
            if enabled.insert(feature) {
                pending.extend(
                    enables
                        .iter()
                        .filter(|entry| !entry.starts_with("dep:") && !entry.contains('/'))
                        .cloned(),
                );
            }
        }
        enabled
    }

    fn table(&self, package: &str) -> &BTreeMap<String, Vec<String>> {
        self.packages
            .get(package)
            .unwrap_or_else(|| panic!("{package} is not a workspace package"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_closure_follows_same_package_implications_only() {
        let features = WorkspaceFeatures::load();
        // wyr1c6-production = ["wyr1c5-production"], wyr1c5 = ["native-init"].
        assert_eq!(
            features.closure("wyrmroot-system-init", "wyr1c6-production"),
            ["native-init", "wyr1c5-production", "wyr1c6-production"]
                .map(str::to_owned)
                .into()
        );
        // `dep:` and `package/feature` entries are not features of this package.
        let r1 = features.closure("wyrmroot-system-init", "r1-selector34");
        assert!(r1.iter().all(|feature| !feature.contains(['/', ':'])));
        assert!(
            features
                .declared("wyrmroot-devmgr")
                .contains("native-devmgr")
        );
    }

    /// Row 254. devmgr's WYR1-E production features enable the neutral
    /// staged connector (D production) and C6, and none of the selector-only
    /// policies that `main.rs`'s `compile_error!` refuses beside them.
    #[test]
    fn devmgr_e_production_enables_the_staged_connector_without_selector_policies() {
        let features = WorkspaceFeatures::load();
        for production in ["wyr1e-production", "wyr1e8-production"] {
            let enabled = features.closure("wyrmroot-devmgr", production);
            assert!(enabled.contains("wyr1d-production"), "{production}");
            assert!(enabled.contains("wyr1c6-production"), "{production}");
            for selector in ["wyr1d-selector32", "dw1e3-selector31", "wyr1c6-selector29"] {
                assert!(
                    !enabled.contains(selector),
                    "{production} enables {selector}"
                );
            }
        }
    }

    /// Row 273. No devmgr feature turns on both the D product's staged
    /// launch and the historical selector-29 actor, and the retained WYR1-A
    /// stubs, which build that actor, have no D-production feature at all.
    #[test]
    fn d_production_never_selects_the_historical_selector29_actor() {
        let features = WorkspaceFeatures::load();
        assert!(
            !features
                .closure("wyrmroot-devmgr", "wyr1d-production")
                .contains("wyr1c6-selector29")
        );
        for feature in features.declared("wyrmroot-devmgr") {
            let enabled = features.closure("wyrmroot-devmgr", feature);
            assert!(
                !(enabled.contains("wyr1d-production") && enabled.contains("wyr1c6-selector29")),
                "devmgr's {feature} enables both D production and selector 29"
            );
        }
        assert!(
            !features
                .declared("wyrmroot-wyr1-retained-stubs")
                .contains("wyr1d-production")
        );
    }
}
