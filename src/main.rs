//! RIAK CLI.
//!
//! Usage:
//!   riak keygen                    — print a random 512-bit hex key
//!   riak legacy-enc <in> <out> --key-file <path> — broken v0.1 research format
//!   riak legacy-dec <in> <out> --key-file <path> — decrypt explicit v0.1 format
//!   (legacy commands require the `legacy-v1` Cargo feature)
//!   riak v2enc <in> <out> --key-file <path> — encrypt with experimental v0.2
//!   riak v2dec <in> <out> --key-file <path> — decrypt an experimental v0.2 file
//!   riak v3enc <in> <out> --key-file <path> — encrypt with experimental v0.3
//!   riak v3dec <in> <out> --key-file <path> — decrypt an experimental v0.3 file
//!   Raw `--key` arguments are rejected so keys do not enter the process list.
//!
//! File formats:
//!   legacy RIAK1: magic "RIAK1" ‖ nonce(12) ‖ framed-tag(16) ‖ ciphertext
//!   experimental v0.2: magic "RIAK2C" ‖ nonce(12) ‖ ciphertext ‖ tag(16)
//!   experimental v0.3: magic "RIAK3C" ‖ nonce(12) ‖ ciphertext ‖ tag(16)
//! (encrypt-then-MAC: tampered files are rejected during decryption).

#![forbid(unsafe_code)]
#![allow(deprecated)]

use riak::{v2, v3};
#[cfg(feature = "legacy-v1")]
use riak::Riak;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process;
use std::process::exit;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

#[cfg(feature = "legacy-v1")]
const MAGIC: &[u8; 5] = b"RIAK1";
const V2_MAGIC: &[u8; 6] = b"RIAK2C";
const V2_HEADER_LEN: usize = V2_MAGIC.len() + 12;
const V3_MAGIC: &[u8; 6] = b"RIAK3C";
const V3_HEADER_LEN: usize = V3_MAGIC.len() + 12;
const MAX_FILE_SIZE: u64 = 64 * 1024 * 1024;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    exit(1);
}

fn parse_key(hex: &str) -> [u8; 64] {
    let hex = hex.trim();
    if !hex.is_ascii() || hex.len() != 128 {
        die("key must be exactly 128 hex chars (512-bit)");
    }
    let mut key = [0u8; 64];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .unwrap_or_else(|_| die("key is not valid hex"));
    }
    key
}

/// Random bytes from the OS (/dev/urandom).
fn os_random(buf: &mut [u8]) {
    use std::io::Read;
    fs::File::open("/dev/urandom")
        .unwrap_or_else(|_| die("cannot open /dev/urandom"))
        .read_exact(buf)
        .unwrap_or_else(|e| die(&format!("cannot read /dev/urandom: {e}")));
}

fn read_file_limited(path: &str) -> Vec<u8> {
    let file = fs::File::open(path)
        .unwrap_or_else(|e| die(&format!("cannot read {path}: {e}")));
    let length = file
        .metadata()
        .unwrap_or_else(|e| die(&format!("cannot stat {path}: {e}")))
        .len();
    if length > MAX_FILE_SIZE {
        die(&format!("{path} exceeds the {MAX_FILE_SIZE}-byte input limit"));
    }

    let mut data = Vec::with_capacity(length as usize);
    let mut read_limit = file.take(MAX_FILE_SIZE + 1);
    read_limit
        .read_to_end(&mut data)
        .unwrap_or_else(|e| die(&format!("cannot read {path}: {e}")));
    if data.len() as u64 > MAX_FILE_SIZE {
        die(&format!("{path} exceeds the {MAX_FILE_SIZE}-byte input limit"));
    }
    data
}

fn write_output(path: &str, data: &[u8]) {
    let target = Path::new(path);
    let parent = target
        .parent()
        .filter(|candidate| !candidate.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = target
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("output");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".{name}.riak-tmp.{}-{stamp}-{sequence}",
        process::id()
    ));

    let result = (|| -> Result<(), String> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&temporary)
            .map_err(|e| format!("cannot create temporary output: {e}"))?;
        file.write_all(data)
            .map_err(|e| format!("cannot write temporary output: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("cannot flush temporary output: {e}"))?;
        drop(file);
        fs::rename(&temporary, target)
            .map_err(|e| format!("cannot install output {path}: {e}"))
    })();

    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        die(&error);
    }
}

fn require_file_args(args: &[String], command: &str) {
    if args.len() != 6 || args[4] != "--key-file" {
        die(&format!(
            "usage: riak {command} <in> <out> --key-file <path> (raw --key is disabled)"
        ));
    }
}

fn key_from_args(args: &[String]) -> [u8; 64] {
    debug_assert_eq!(args[4], "--key-file");
    let path = &args[5];
    #[cfg(unix)]
    if fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        die(&format!("key file {path} must not be a symlink"));
    }
    let mut file = fs::File::open(path)
        .unwrap_or_else(|e| die(&format!("cannot open key file {path}: {e}")));
    let metadata = file
        .metadata()
        .unwrap_or_else(|e| die(&format!("cannot stat key file {path}: {e}")));
    if !metadata.is_file() {
        die(&format!("key file {path} is not a regular file"));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        die("key file must not be group/world accessible (use chmod 600)");
    }

    let mut text = String::new();
    file.read_to_string(&mut text)
        .unwrap_or_else(|e| die(&format!("cannot read key file {path}: {e}")));
    parse_key(&text)
}

fn encrypt_v2_file(args: &[String]) {
    eprintln!("warning: RIAK2C v0.2 is unvalidated and rejected for production");
    require_file_args(args, "v2enc");
    let key = key_from_args(args);
    let cipher = v2::RiakV2Cipher::new(&key);
    let mut nonce = [0u8; 12];
    os_random(&mut nonce);
    let plaintext = read_file_limited(&args[2]);

    let mut header = Vec::with_capacity(V2_HEADER_LEN);
    header.extend_from_slice(V2_MAGIC);
    header.extend_from_slice(&nonce);
    let sealed = cipher
        .seal(&nonce, &header, &plaintext)
        .unwrap_or_else(|e| die(&format!("v0.2 encryption failed: {e}")));

    let mut output = header;
    output.extend_from_slice(&sealed);
    write_output(&args[3], &output);
}

fn decrypt_v2_file(args: &[String]) {
    eprintln!("warning: RIAK2C v0.2 is unvalidated and rejected for production");
    require_file_args(args, "v2dec");
    let key = key_from_args(args);
    let cipher = v2::RiakV2Cipher::new(&key);
    let data = read_file_limited(&args[2]);

    if data.len() < V2_HEADER_LEN + v2::AUTH_TAG_LEN
        || &data[..V2_MAGIC.len()] != V2_MAGIC
    {
        die("not a RIAK2C v0.2 file");
    }

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&data[V2_MAGIC.len()..V2_HEADER_LEN]);
    let header = &data[..V2_HEADER_LEN];
    let plaintext = cipher
        .open(&nonce, header, &data[V2_HEADER_LEN..])
        .unwrap_or_else(|e| die(&format!("v0.2 authentication/decryption failed: {e}")));

    write_output(&args[3], &plaintext);
}

fn encrypt_v3_file(args: &[String]) {
    eprintln!("warning: RIAK3C v0.3 is experimental and not externally audited");
    require_file_args(args, "v3enc");
    let key = key_from_args(args);
    let cipher = v3::RiakV3Cipher::new(&key);
    let mut nonce = [0u8; 12];
    os_random(&mut nonce);
    let plaintext = read_file_limited(&args[2]);

    let mut header = Vec::with_capacity(V3_HEADER_LEN);
    header.extend_from_slice(V3_MAGIC);
    header.extend_from_slice(&nonce);
    let sealed = cipher
        .seal(&nonce, &header, &plaintext)
        .unwrap_or_else(|e| die(&format!("v0.3 encryption failed: {e}")));
    let mut output = header;
    output.extend_from_slice(&sealed);
    write_output(&args[3], &output);
}

fn decrypt_v3_file(args: &[String]) {
    eprintln!("warning: RIAK3C v0.3 is experimental and not externally audited");
    require_file_args(args, "v3dec");
    let key = key_from_args(args);
    let cipher = v3::RiakV3Cipher::new(&key);
    let data = read_file_limited(&args[2]);

    if data.len() < V3_HEADER_LEN + v3::AUTH_TAG_LEN
        || &data[..V3_MAGIC.len()] != V3_MAGIC
    {
        die("not a RIAK3C v0.3 file");
    }

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&data[V3_MAGIC.len()..V3_HEADER_LEN]);
    let header = &data[..V3_HEADER_LEN];
    let plaintext = cipher
        .open(&nonce, header, &data[V3_HEADER_LEN..])
        .unwrap_or_else(|e| die(&format!("v0.3 authentication/decryption failed: {e}")));
    write_output(&args[3], &plaintext);
}

#[cfg(feature = "legacy-v1")]
fn encrypt_legacy_file(args: &[String]) {
    eprintln!("warning: RIAK1 v0.1 is broken and retained only for reproducible research");
    require_file_args(args, "legacy-enc");
    let key = key_from_args(args);
    let cipher = Riak::new(&key);
    let data = read_file_limited(&args[2]);
    let mut nonce = [0u8; 12];
    os_random(&mut nonce);
    let ciphertext = cipher.encrypt(&nonce, &data);
    let mut header = Vec::with_capacity(MAGIC.len() + nonce.len());
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&nonce);
    let tag = cipher.mac_framed(&header, &nonce, &ciphertext);
    let mut output = header;
    output.extend_from_slice(&tag);
    output.extend_from_slice(&ciphertext);
    write_output(&args[3], &output);
}

#[cfg(feature = "legacy-v1")]
fn decrypt_legacy_file(args: &[String]) {
    eprintln!("warning: RIAK1 v0.1 is broken and retained only for reproducible research");
    require_file_args(args, "legacy-dec");
    let key = key_from_args(args);
    let cipher = Riak::new(&key);
    let data = read_file_limited(&args[2]);
    let header_len = MAGIC.len() + 12;
    if data.len() < header_len + 16 || &data[..MAGIC.len()] != MAGIC {
        die("not a RIAK1 file");
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&data[MAGIC.len()..header_len]);
    let tag: [u8; 16] = data[header_len..header_len + 16].try_into().unwrap();
    let ciphertext = &data[header_len + 16..];
    let header = &data[..header_len];
    if !cipher.verify_framed(header, &nonce, ciphertext, &tag) {
        die("MAC verification FAILED — file was tampered with or wrong key");
    }
    let plaintext = cipher.decrypt(&nonce, ciphertext);
    write_output(&args[3], &plaintext);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        die("usage: riak <keygen|legacy-enc|legacy-dec|v2enc|v2dec|v3enc|v3dec> [args] — see module docs");
    }
    match args[1].as_str() {
        "keygen" => {
            let mut key = [0u8; 64];
            os_random(&mut key);
            let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
            println!("{hex}");
        }
        "v2enc" => encrypt_v2_file(&args),
        "v2dec" => decrypt_v2_file(&args),
        "v3enc" => encrypt_v3_file(&args),
        "v3dec" => decrypt_v3_file(&args),
        #[cfg(feature = "legacy-v1")]
        "legacy-enc" => encrypt_legacy_file(&args),
        #[cfg(feature = "legacy-v1")]
        "legacy-dec" => decrypt_legacy_file(&args),
        "enc" | "dec" => die(
            "legacy enc/dec were removed; use legacy-enc/legacy-dec with --key-file explicitly",
        ),
        other => die(&format!("unknown command: {other}")),
    }
}
