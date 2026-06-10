use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
pub const AUTH_TAG_LEN: usize = 32;

pub fn compute_auth_tag_bytes(
    client_secret: &[u8],
    nonce: &[u8],
    timestamp: i64,
    client_id: &str,
) -> Result<[u8; AUTH_TAG_LEN], hmac::digest::InvalidLength> {
    let mut mac = HmacSha256::new_from_slice(client_secret)?;
    mac.update(nonce);
    mac.update(&timestamp.to_be_bytes());
    mac.update(client_id.as_bytes());
    let tag = mac.finalize().into_bytes();
    Ok(tag.into())
}
