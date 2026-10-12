use anyhow::{bail, Result};

/// Validate the raw `groups` entries resolved from CLI/config, before
/// [`crate::poster`]'s `pick_post_group` ever sees them.
///
/// Each entry is either a single newsgroup name, or several names joined
/// with `+` for a simultaneous cross-post (e.g. `"a.b.c+d.e.f"`). `,` is
/// accepted as a deprecated alias for `+` — before this was formalized, a
/// TOML array element with an embedded `,` (unlike `--groups` on the CLI,
/// which already splits on `,`) passed straight through to the `Newsgroups:`
/// header and happened to cross-post, purely as a parsing accident. Existing
/// configs relying on that keep working, with a nudge towards `+`, rather
/// than a hard break on upgrade.
pub fn validate_groups(groups: &[String]) -> Result<()> {
    for entry in groups {
        if entry.contains(',') {
            eprintln!(
                "warning: newsgroup entry `{entry}` uses ',' to cross-post — ',' is \
                 deprecated for this, use '+' instead (e.g. \"a.b.c+d.e.f\"); ',' will stop \
                 being treated as a cross-post separator in a future release"
            );
        }
        for part in entry.split(['+', ',']) {
            if part.trim().is_empty() {
                bail!("newsgroup entry `{entry}` has an empty name around '+'/','");
            }
        }
    }
    Ok(())
}

/// Check whether `s` consists strictly of valid XML 1.0 characters.
///
/// XML 1.0 Section 2.2 defines valid Char as:
/// `#x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]`
pub fn is_xml_representable(s: &str) -> bool {
    s.chars().all(|c| {
        matches!(
            c,
            '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}'
        )
    })
}

/// Validate encryption password configuration.
///
/// - Rejects empty password strings.
/// - Rejects XML-unrepresentable transport password characters before posting (STD-3).
/// - Preserves valid whitespace (LF, tab, CR) and non-ASCII UTF-8 bytes verbatim without altering.
/// - Rejects conflicting passwords if both `encrypt_password` and `nzb_password` are specified and differ.
/// - Rejects a conflicting archive password (`--password`/`compress_password`)
///   when it differs from `encrypt_password` — see
///   [`validate_password_compatibility`].
pub fn validate_encryption(
    encrypt_password: Option<&str>,
    nzb_password: Option<&str>,
    compress_password: Option<&str>,
) -> Result<()> {
    if let Some(pw) = encrypt_password {
        if pw.is_empty() {
            bail!("encryption password cannot be empty");
        }
        if !is_xml_representable(pw) {
            bail!("encryption password contains characters that cannot be represented in XML");
        }
        if let Some(nzb_pw) = nzb_password {
            if nzb_pw.is_empty() {
                bail!("nzb password cannot be empty");
            }
            if !is_xml_representable(nzb_pw) {
                bail!("nzb password contains characters that cannot be represented in XML");
            }
            if nzb_pw != pw {
                bail!("conflicting passwords: --encrypt-password and --nzb-password cannot differ");
            }
        }
        validate_password_compatibility(compress_password, Some(pw))?;
    }
    Ok(())
}

/// Explicit compatible-password rule for the archive (transport) vs yEnc
/// encryption password pair (yEnc Body Encryption Standard v1.2 §8).
///
/// `<meta type="password">` is the only interoperable password channel in an
/// NZB, and an encrypted upload writes the *encryption* password there (a
/// downloader needs it before it can even see the archive inside). When
/// compression also runs with a password, that archive password has no wire
/// representation: if the two differ, every downloader would decrypt the
/// articles successfully and then fail archive extraction with a password it
/// was never given — the archive password would be silently lost. Rather
/// than inventing a second metadata field, conflicting combinations are
/// rejected before any posting work; equal passwords are accepted (the same
/// value legitimately protects both the archive and the transport).
pub fn validate_password_compatibility(
    archive_password: Option<&str>,
    encrypt_password: Option<&str>,
) -> Result<()> {
    if let (Some(archive_pw), Some(encrypt_pw)) = (archive_password, encrypt_password) {
        if archive_pw != encrypt_pw {
            bail!(
                "conflicting passwords: the archive password (--password) and the yEnc \
                 encryption password (--encrypt-password) cannot differ — the NZB \
                 <meta type=\"password\"> carries only the encryption password, so a \
                 different archive password would be lost to every downloader; use the \
                 same password for both, or drop --password"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_validation_empty_password_rejected() {
        assert!(validate_encryption(Some(""), None, None).is_err());
    }

    #[test]
    fn encryption_validation_whitespace_passwords_follow_std3_no_alteration() {
        // STD-3: no silent alteration. A whitespace-only password is a valid
        // (if unusual) secret — it round-trips through XML verbatim, so it
        // is accepted as-is. Only the empty string and XML-unrepresentable
        // bytes are rejected.
        assert!(validate_encryption(Some("   "), None, None).is_ok());
        assert!(validate_encryption(Some("\t\n"), None, None).is_ok());
        // Empty nzb override is still rejected; a whitespace-only one that
        // MATCHES the encryption password is the same secret.
        assert!(validate_encryption(Some("secret"), Some(""), None).is_err());
        assert!(validate_encryption(Some("secret"), Some("other"), None).is_err());
    }

    #[test]
    fn encryption_validation_valid_password_accepted() {
        assert!(validate_encryption(Some("secret"), None, None).is_ok());
        assert!(validate_encryption(Some("secret"), Some("secret"), None).is_ok());
    }

    #[test]
    fn encryption_validation_conflicting_passwords_rejected() {
        assert!(validate_encryption(Some("secret"), Some("other"), None).is_err());
    }

    #[test]
    fn encryption_validation_none_accepted() {
        assert!(validate_encryption(None, None, None).is_ok());
        assert!(validate_encryption(None, Some("nzbpass"), None).is_ok());
        assert!(validate_encryption(None, None, Some("archive")).is_ok());
    }

    #[test]
    fn matching_archive_and_encrypt_passwords_accepted() {
        // Same password protecting archive and transport is the accepted
        // combination: the NZB meta describes both.
        assert!(validate_password_compatibility(Some("shared"), Some("shared")).is_ok());
        assert!(validate_encryption(Some("shared"), None, Some("shared")).is_ok());
    }

    #[test]
    fn conflicting_archive_and_encrypt_passwords_rejected() {
        // `--password A --encrypt E` (A != E): the NZB can carry only E, so
        // the archive password would be silently lost — reject before any
        // posting work.
        let err = validate_password_compatibility(Some("archive-pw"), Some("encrypt-pw"))
            .expect_err("conflicting archive/encrypt passwords must be rejected");
        assert!(err.to_string().contains("conflicting passwords"));

        assert!(validate_encryption(Some("encrypt-pw"), None, Some("archive-pw")).is_err());
        // The encryption-vs-nzb rule still wins with a distinct message.
        let err2 = validate_encryption(Some("secret"), Some("other"), Some("secret"))
            .expect_err("conflicting encrypt/nzb passwords must still be rejected");
        assert!(err2.to_string().contains("--nzb-password"));
    }

    #[test]
    fn single_group_is_valid() {
        assert!(validate_groups(&["alt.binaries.test".to_string()]).is_ok());
    }

    #[test]
    fn cross_post_target_is_valid() {
        assert!(validate_groups(&["alt.binaries.a+alt.binaries.b".to_string()]).is_ok());
    }

    #[test]
    fn pool_of_targets_is_valid() {
        let groups = vec![
            "alt.binaries.a+alt.binaries.b".to_string(),
            "alt.binaries.c".to_string(),
        ];
        assert!(validate_groups(&groups).is_ok());
    }

    #[test]
    fn comma_is_accepted_as_deprecated_alias() {
        // Warns on stderr (not asserted here, matching this crate's other
        // eprintln!-based warnings, e.g. walk.rs) but does not error.
        assert!(validate_groups(&["alt.binaries.a,alt.binaries.b".to_string()]).is_ok());
    }

    #[test]
    fn trailing_plus_is_rejected() {
        assert!(validate_groups(&["alt.binaries.a+".to_string()]).is_err());
    }

    #[test]
    fn leading_plus_is_rejected() {
        assert!(validate_groups(&["+alt.binaries.a".to_string()]).is_err());
    }

    #[test]
    fn double_plus_is_rejected() {
        assert!(validate_groups(&["alt.binaries.a++alt.binaries.b".to_string()]).is_err());
    }

    #[test]
    fn trailing_comma_is_rejected() {
        assert!(validate_groups(&["alt.binaries.a,".to_string()]).is_err());
    }

    #[test]
    fn whitespace_only_part_is_rejected() {
        assert!(validate_groups(&["alt.binaries.a+   ".to_string()]).is_err());
    }
}
