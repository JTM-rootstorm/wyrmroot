//! Strict optional WYR1-A live-gate configuration from retained bootfs.

pub const GATE_CONFIG_PATH: &str = "system/bootstrap/wyr1-a-gate-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateScenario {
    Normal,
    DegradedRecovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GateConfig {
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
    exact(lines.next(), "selector = \"permanent-supervisor-rrc\"")?;
    exact(lines.next(), "test_id = 25")?;
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
    Ok(GateConfig { scenario, nonce })
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

    #[test]
    fn accepts_exact_contract_and_rejects_drift() {
        assert_eq!(
            parse_gate_config(NORMAL),
            Ok(GateConfig {
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
}
