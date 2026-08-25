//! Exact selector-owned bootfs configuration and immutable asset contract.

use crate::sha256;

pub const CONFIG_BOOTFS_PATH: &[u8] = b"test/wyr0-i/config.toml";
pub const ASSET_BOOTFS_PATH: &[u8] = b"test/wyr0-i/asset.bin";
pub const CANONICAL_CONFIG_SOURCE: &[u8] = include_bytes!("../assets/config.toml");
pub const CANONICAL_ASSET_SOURCE: &[u8] = include_bytes!("../assets/asset.bin");

const PREFIX: &[u8] = b"schema_version=1\nselector=\"native-userspace-capability\"\ntest_id=24\nevidence_protocol=\"wrcap1\"\nevidence_nonce=\"";
const MIDDLE: &[u8] = b"\"\nasset_sha256=\"";
const SUFFIX: &[u8] = b"\"\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectorContent {
    pub evidence_nonce: u64,
    pub config_sha256: [u8; 32],
    pub asset_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentError {
    MalformedConfig,
    InvalidNonce,
    InvalidAssetDigest,
    AssetContentMismatch,
    AssetDigestMismatch,
}

pub fn validate_selector_content(
    config: &[u8],
    asset: &[u8],
) -> Result<SelectorContent, ContentError> {
    let nonce_start = PREFIX.len();
    let nonce_end = nonce_start + 16;
    let middle_end = nonce_end + MIDDLE.len();
    let digest_end = middle_end + 64;
    let expected_len = digest_end + SUFFIX.len();
    if config.len() != expected_len
        || config.get(..nonce_start) != Some(PREFIX)
        || config.get(nonce_end..middle_end) != Some(MIDDLE)
        || config.get(digest_end..) != Some(SUFFIX)
    {
        return Err(ContentError::MalformedConfig);
    }

    let nonce_bytes = config
        .get(nonce_start..nonce_end)
        .ok_or(ContentError::MalformedConfig)?;
    if !nonce_bytes
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(byte))
    {
        return Err(ContentError::InvalidNonce);
    }
    let evidence_nonce = parse_hex_u64(nonce_bytes).ok_or(ContentError::InvalidNonce)?;
    if evidence_nonce == 0 {
        return Err(ContentError::InvalidNonce);
    }

    let digest_bytes = config
        .get(middle_end..digest_end)
        .ok_or(ContentError::MalformedConfig)?;
    if !digest_bytes
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(ContentError::InvalidAssetDigest);
    }
    let expected_asset_digest =
        parse_digest(digest_bytes).ok_or(ContentError::InvalidAssetDigest)?;
    if asset != CANONICAL_ASSET_SOURCE {
        return Err(ContentError::AssetContentMismatch);
    }
    let asset_sha256 = sha256::digest(asset);
    if asset_sha256 != expected_asset_digest {
        return Err(ContentError::AssetDigestMismatch);
    }

    Ok(SelectorContent {
        evidence_nonce,
        config_sha256: sha256::digest(config),
        asset_sha256,
    })
}

fn parse_hex_u64(bytes: &[u8]) -> Option<u64> {
    let mut value = 0_u64;
    for byte in bytes {
        value = value
            .checked_mul(16)?
            .checked_add(u64::from(nibble(*byte)?))?;
    }
    Some(value)
}

fn parse_digest(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() != 64 {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        output[index] = nibble(pair[0])?
            .checked_mul(16)?
            .checked_add(nibble(pair[1])?)?;
    }
    Some(output)
}

const fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_content_is_exact_and_request_bound() {
        let content = validate_selector_content(CANONICAL_CONFIG_SOURCE, CANONICAL_ASSET_SOURCE)
            .expect("canonical selector content");
        assert_eq!(content.evidence_nonce, 0x0123_4567_89AB_CDEF);
        assert_eq!(
            sha256::prefix_u64(&content.asset_sha256),
            0xC0E8_3E5C_6751_8828
        );
    }

    #[test]
    fn rejects_extra_wrong_case_and_mismatched_content() {
        let mut extra = CANONICAL_CONFIG_SOURCE.to_vec();
        extra.extend_from_slice(b"extra=1\n");
        assert_eq!(
            validate_selector_content(&extra, CANONICAL_ASSET_SOURCE),
            Err(ContentError::MalformedConfig)
        );

        let mut nonce_case = CANONICAL_CONFIG_SOURCE.to_vec();
        let index = nonce_case
            .windows(16)
            .position(|window| window == b"0123456789ABCDEF")
            .unwrap();
        nonce_case[index + 10] = b'a';
        assert_eq!(
            validate_selector_content(&nonce_case, CANONICAL_ASSET_SOURCE),
            Err(ContentError::InvalidNonce)
        );

        let mut asset = CANONICAL_ASSET_SOURCE.to_vec();
        asset[0] ^= 1;
        assert_eq!(
            validate_selector_content(CANONICAL_CONFIG_SOURCE, &asset),
            Err(ContentError::AssetContentMismatch)
        );
    }
}
