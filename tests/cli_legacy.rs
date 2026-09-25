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
fn legacy_cli_still_roundtrips() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("riak-legacy-cli-{}-{stamp}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let input = dir.join("input");
    let encrypted = dir.join("input.riak");
    let output = dir.join("output");
    fs::write(&input, b"legacy compatibility test\n").unwrap();

    let key = hex_key();
    let binary = env!("CARGO_BIN_EXE_riak");
    let status = Command::new(binary)
        .args(["enc"])
        .arg(&input)
        .arg(&encrypted)
        .args(["--key", &key])
        .status()
        .unwrap();
    assert!(status.success());
    let status = Command::new(binary)
        .args(["dec"])
        .arg(&encrypted)
        .arg(&output)
        .args(["--key", &key])
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(fs::read(output).unwrap(), fs::read(input).unwrap());
    let _ = fs::remove_dir_all(dir);
}
