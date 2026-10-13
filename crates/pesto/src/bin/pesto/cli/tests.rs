use super::*;
use clap::Parser;

#[test]
fn test_bare_encrypt_preserves_positional_files() {
    let args = vec!["pesto", "--encrypt", "file.mkv"];
    let cli = Cli::try_parse_from(args).expect("parsing should succeed");
    assert_eq!(cli.encrypt, Some("".to_string()));
    assert_eq!(cli.files, vec![PathBuf::from("file.mkv")]);
}

#[test]
fn test_explicit_encrypt_with_equals_preserves_positional_files() {
    let args = vec!["pesto", "--encrypt=my_secret", "file.mkv"];
    let cli = Cli::try_parse_from(args).expect("parsing should succeed");
    assert_eq!(cli.encrypt, Some("my_secret".to_string()));
    assert_eq!(cli.files, vec![PathBuf::from("file.mkv")]);
}

#[test]
fn test_encrypt_password_preserves_positional_files() {
    let args = vec!["pesto", "--encrypt-password", "my_secret", "file.mkv"];
    let cli = Cli::try_parse_from(args).expect("parsing should succeed");
    assert_eq!(cli.encrypt_password, Some("my_secret".to_string()));
    assert_eq!(cli.files, vec![PathBuf::from("file.mkv")]);
}
