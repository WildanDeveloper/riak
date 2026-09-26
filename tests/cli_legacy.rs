#![cfg(feature = "legacy-v1")]

use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn hex_key() -> String {
    let mut key = [0u8; 64];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = (255 - i) as u8;
    }
    key.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn legacy_cli_is_explicit_and_authenticates_its_header() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("riak-legacy-cli-{}-{stamp}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let input = dir.join("input");
    let encrypted = dir.join("input.riak");
    let output = dir.join("output");
    let key_file = dir.join("key.hex");
    fs::write(&input, b"legacy compatibility test\n").unwrap();
    fs::write(&key_file, format!("{}\n", hex_key())).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let binary = env!("CARGO_BIN_EXE_riak");
    let status = Command::new(binary)
        .args(["legacy-enc"])
        .arg(&input)
        .arg(&encrypted)
        .args(["--key-file"])
        .arg(&key_file)
        .status()
        .unwrap();
    assert!(status.success());
    let status = Command::new(binary)
        .args(["legacy-dec"])
        .arg(&encrypted)
        .arg(&output)
        .args(["--key-file"])
        .arg(&key_file)
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(fs::read(output).unwrap(), fs::read(&input).unwrap());

    let mut tampered = fs::read(&encrypted).unwrap();
    tampered[5] ^= 1;
    let tampered_path = dir.join("nonce-tampered.riak");
    fs::write(&tampered_path, tampered).unwrap();
    let status = Command::new(binary)
        .args(["legacy-dec"])
        .arg(&tampered_path)
        .arg(dir.join("bad-nonce.txt"))
        .args(["--key-file"])
        .arg(&key_file)
        .status()
        .unwrap();
    assert!(!status.success(), "legacy header/nonce must be authenticated");

    let status = Command::new(binary)
        .args(["enc"])
        .arg(&input)
        .arg(dir.join("disabled.riak"))
        .args(["--key-file"])
        .arg(&key_file)
        .status()
        .unwrap();
    assert!(!status.success(), "legacy enc alias must not be available");

    let _ = fs::remove_dir_all(dir);
}
