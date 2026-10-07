//! Argon2id wrapper: the single normative parameter set (time=1, memory=64MB,
//! threads=4, 32-byte output) shared by body and control-line key derivation.

use argon2::Algorithm::Argon2id;
use argon2::Params;
use argon2::Version::V0x13;

use super::keys::SALT_LEN;

/// Argon2id(password, salt, time=1, memory=64MB, threads=4, 32-byte out).
pub(crate) fn argon2id(password: &[u8], salt: &[u8; SALT_LEN]) -> [u8; 32] {
    let params = Params::new(64 * 1024, 1, 4, Some(32)).expect("normative Argon2 parameters");
    let mut out = [0u8; 32];
    argon2::Argon2::new(Argon2id, V0x13, params)
        .hash_password_into(password, salt, &mut out)
        .expect("Argon2id derivation into a 32-byte buffer");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        let salt = [0x1au8; SALT_LEN];
        let a = argon2id(b"test123", &salt);
        let b = argon2id(b"test123", &salt);
        assert_eq!(a, b);
        let c = argon2id(b"other", &salt);
        assert_ne!(a, c);
    }
}
