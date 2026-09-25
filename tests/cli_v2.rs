use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn hex_key() -> String {
    let mut key = [0u8; 64];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = i as u8;
    }
    key.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn temp_dir() -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("riak-v2-cli-{}-{stamp}", std::process::id()))
}

#[test]
fn v2_cli_roundtrip_and_tamper_rejection() {
    let dir = temp_dir();
    fs::create_dir_all(&dir).unwrap();
    let input = dir.join("input.txt");
    let encrypted = dir.join("input.riak2c");
    let output = dir.join("output.txt");
    let tampered = dir.join("tampered.riak2c");
    fs::write(&input, b"v0.2 CLI integration test\n").unwrap();

    let key = hex_key();
    let key_file = dir.join("key.hex");
    fs::write(&key_file, format!("{key}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let binary = env!("CARGO_BIN_EXE_riak");
    let status = Command::new(binary)
        .args(["v2enc"])
        .arg(&input)
        .arg(&encrypted)
        .args(["--key", &key])
        .status()
        .unwrap();
    assert!(status.success());

    let status = Command::new(binary)
        .args(["v2dec"])
        .arg(&encrypted)
        .arg(&output)
        .args(["--key", &key])
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(fs::read(&output).unwrap(), fs::read(&input).unwrap());

    let key_file_encrypted = dir.join("key-file.riak2c");
    let key_file_output = dir.join("key-file-output.txt");
    let status = Command::new(binary)
        .args(["v2enc"])
        .arg(&input)
        .arg(&key_file_encrypted)
        .args(["--key-file"])
        .arg(&key_file)
        .status()
        .unwrap();
    assert!(status.success());
    let status = Command::new(binary)
        .args(["v2dec"])
        .arg(&key_file_encrypted)
        .arg(&key_file_output)
        .args(["--key-file"])
        .arg(&key_file)
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(fs::read(&key_file_output).unwrap(), fs::read(&input).unwrap());

    let mut bytes = fs::read(&encrypted).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&tampered, bytes).unwrap();
    let status = Command::new(binary)
        .args(["v2dec"])
        .arg(&tampered)
        .arg(dir.join("bad.txt"))
        .args(["--key", &key])
        .status()
        .unwrap();
    assert!(!status.success());

    let nonce_tampered = dir.join("nonce-tampered.riak2c");
    let mut bytes = fs::read(&encrypted).unwrap();
    bytes[6] ^= 1;
    fs::write(&nonce_tampered, bytes).unwrap();
    let status = Command::new(binary)
        .args(["v2dec"])
        .arg(&nonce_tampered)
        .arg(dir.join("bad-nonce.txt"))
        .args(["--key", &key])
        .status()
        .unwrap();
    assert!(!status.success());

    let bad_magic = dir.join("bad-magic.riak2c");
    let mut bytes = fs::read(&encrypted).unwrap();
    bytes[0] ^= 1;
    fs::write(&bad_magic, bytes).unwrap();
    let status = Command::new(binary)
        .args(["v2dec"])
        .arg(&bad_magic)
        .arg(dir.join("bad-magic.txt"))
        .args(["--key", &key])
        .status()
        .unwrap();
    assert!(!status.success());

    let _ = fs::remove_dir_all(dir);
}
