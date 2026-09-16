//! Strict optional WYR1-A live-gate configuration from retained bootfs.

pub const GATE_CONFIG_PATH: &str = "system/bootstrap/wyr1-a-gate-v1";

/// Which selector's gate contract a configuration file declares.
///
/// The file shape is shared, but the selector/test-id pair is not: admitting
/// one pair's file under the other's selector would let a historical WYR1-A
/// regression product drive the final closure episode, or the reverse. The
/// parser therefore reports the pair rather than erasing it, and callers that
/// care must check it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateContract {
    /// Selector 25, `permanent-supervisor-rrc`: the historical WYR1-A
    /// supervisor regression.
    PermanentSupervisorRrc,
    /// Selector 35, `dw1-wyr1-interactive-closure`: the DW1-F/WYR1-F final
    /// closure selector frozen by `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` §4.
    Dw1Wyr1InteractiveClosure,
}

impl GateContract {
    const fn from_lines(selector: &str, test_id: &str) -> Option<Self> {
        match (selector.as_bytes(), test_id.as_bytes()) {
            (b"selector = \"permanent-supervisor-rrc\"", b"test_id = 25") => {
                Some(Self::PermanentSupervisorRrc)
            }
            (b"selector = \"dw1-wyr1-interactive-closure\"", b"test_id = 35") => {
                Some(Self::Dw1Wyr1InteractiveClosure)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateScenario {
    Normal,
    DegradedRecovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GateConfig {
    pub contract: GateContract,
    pub scenario: GateScenario,
    pub nonce: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateConfigError {
    InvalidUtf8,
    WrongContract,
    InvalidNonce,
}

pub fn parse_gate_config(bytes: &[u8]) -> Result<GateConfig, GateConfigError> {
    let text = core::str::from_utf8(bytes).map_err(|_| GateConfigError::InvalidUtf8)?;
    let mut lines = text.lines();
    exact(lines.next(), "schema = 1")?;
    // The selector and its test id are read as one pair. Checking them apart
    // would admit a file naming one selector with the other's id.
    let contract = match (lines.next(), lines.next()) {
        (Some(selector), Some(test_id)) => {
            GateContract::from_lines(selector, test_id).ok_or(GateConfigError::WrongContract)?
        }
        _ => return Err(GateConfigError::WrongContract),
    };
    let scenario = match lines.next() {
        Some("scenario = \"normal\"") => GateScenario::Normal,
        Some("scenario = \"degraded_recovery\"") => GateScenario::DegradedRecovery,
        _ => return Err(GateConfigError::WrongContract),
    };
    exact(lines.next(), "evidence_protocol = \"wyr1evid1\"")?;
    let nonce = lines
        .next()
        .and_then(|line| line.strip_prefix("nonce = \""))
        .and_then(|line| line.strip_suffix('"'))
        .ok_or(GateConfigError::WrongContract)?;
    if nonce.len() != 16
        || !nonce
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F'))
        || lines.next().is_some()
    {
        return Err(GateConfigError::WrongContract);
    }
    let nonce = u64::from_str_radix(nonce, 16).map_err(|_| GateConfigError::InvalidNonce)?;
    if nonce == 0 {
        return Err(GateConfigError::InvalidNonce);
    }
    Ok(GateConfig {
        contract,
        scenario,
        nonce,
    })
}

fn exact(actual: Option<&str>, expected: &str) -> Result<(), GateConfigError> {
    if actual == Some(expected) {
        Ok(())
    } else {
        Err(GateConfigError::WrongContract)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NORMAL: &[u8] = b"schema = 1\nselector = \"permanent-supervisor-rrc\"\ntest_id = 25\nscenario = \"normal\"\nevidence_protocol = \"wyr1evid1\"\nnonce = \"0123456789ABCDEF\"\n";
    const CLOSURE_DEGRADED: &[u8] = b"schema = 1\nselector = \"dw1-wyr1-interactive-closure\"\ntest_id = 35\nscenario = \"degraded_recovery\"\nevidence_protocol = \"wyr1evid1\"\nnonce = \"00000000000000FF\"\n";

    #[test]
    fn accepts_exact_contract_and_rejects_drift() {
        assert_eq!(
            parse_gate_config(NORMAL),
            Ok(GateConfig {
                contract: GateContract::PermanentSupervisorRrc,
                scenario: GateScenario::Normal,
                nonce: 0x0123_4567_89ab_cdef,
            })
        );
        let mut extra = NORMAL.to_vec();
        extra.extend_from_slice(b"extra = 1\n");
        assert_eq!(
            parse_gate_config(&extra),
            Err(GateConfigError::WrongContract)
        );
    }

    #[test]
    fn accepts_the_final_closure_selector_without_widening_the_shape() {
        assert_eq!(
            parse_gate_config(CLOSURE_DEGRADED),
            Ok(GateConfig {
                contract: GateContract::Dw1Wyr1InteractiveClosure,
                scenario: GateScenario::DegradedRecovery,
                nonce: 0xff,
            })
        );
        // Everything except the selector/test-id pair is still exact.
        for broken in [
            b"schema = 2\nselector = \"dw1-wyr1-interactive-closure\"\ntest_id = 35\nscenario = \"normal\"\nevidence_protocol = \"wyr1evid1\"\nnonce = \"00000000000000FF\"\n".as_slice(),
            b"schema = 1\nselector = \"dw1-wyr1-interactive-closure\"\ntest_id = 35\nscenario = \"degraded\"\nevidence_protocol = \"wyr1evid1\"\nnonce = \"00000000000000FF\"\n".as_slice(),
            b"schema = 1\nselector = \"dw1-wyr1-interactive-closure\"\ntest_id = 35\nscenario = \"normal\"\nevidence_protocol = \"wre1\"\nnonce = \"00000000000000FF\"\n".as_slice(),
        ] {
            assert_eq!(parse_gate_config(broken), Err(GateConfigError::WrongContract));
        }
    }

    /// The two selectors' ids are not interchangeable, and neither is any
    /// unallocated id. Test id 34 is `dynamic-launch-saturation`.
    #[test]
    fn rejects_a_mismatched_or_unallocated_selector_and_id_pair() {
        for crossed in [
            b"schema = 1\nselector = \"permanent-supervisor-rrc\"\ntest_id = 35\nscenario = \"normal\"\nevidence_protocol = \"wyr1evid1\"\nnonce = \"00000000000000FF\"\n".as_slice(),
            b"schema = 1\nselector = \"dw1-wyr1-interactive-closure\"\ntest_id = 25\nscenario = \"normal\"\nevidence_protocol = \"wyr1evid1\"\nnonce = \"00000000000000FF\"\n".as_slice(),
            b"schema = 1\nselector = \"dw1-wyr1-interactive-closure\"\ntest_id = 34\nscenario = \"normal\"\nevidence_protocol = \"wyr1evid1\"\nnonce = \"00000000000000FF\"\n".as_slice(),
            b"schema = 1\nselector = \"dynamic-launch-saturation\"\ntest_id = 34\nscenario = \"normal\"\nevidence_protocol = \"wyr1evid1\"\nnonce = \"00000000000000FF\"\n".as_slice(),
        ] {
            assert_eq!(
                parse_gate_config(crossed),
                Err(GateConfigError::WrongContract)
            );
        }
    }

    /// The normal *production* gate config is not a gate contract at all, and
    /// must stay unparseable: ordinary boot takes no scenario and no nonce.
    /// See `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` §5.4 as amended by F1A.1 §1.3.
    #[test]
    fn rejects_the_uninstrumented_production_configuration() {
        assert_eq!(
            parse_gate_config(
                b"schema = 1\nproduct = \"wyr1-f-normal\"\nselector = \"none\"\nevidence = \"not-produced\"\n"
            ),
            Err(GateConfigError::WrongContract)
        );
    }

    #[test]
    fn rejects_a_zero_or_malformed_nonce() {
        assert_eq!(
            parse_gate_config(
                b"schema = 1\nselector = \"dw1-wyr1-interactive-closure\"\ntest_id = 35\nscenario = \"normal\"\nevidence_protocol = \"wyr1evid1\"\nnonce = \"0000000000000000\"\n"
            ),
            Err(GateConfigError::InvalidNonce)
        );
        for malformed in [
            b"schema = 1\nselector = \"dw1-wyr1-interactive-closure\"\ntest_id = 35\nscenario = \"normal\"\nevidence_protocol = \"wyr1evid1\"\nnonce = \"00000000000000ff\"\n".as_slice(),
            b"schema = 1\nselector = \"dw1-wyr1-interactive-closure\"\ntest_id = 35\nscenario = \"normal\"\nevidence_protocol = \"wyr1evid1\"\nnonce = \"FF\"\n".as_slice(),
        ] {
            assert_eq!(
                parse_gate_config(malformed),
                Err(GateConfigError::WrongContract)
            );
        }
    }
}
