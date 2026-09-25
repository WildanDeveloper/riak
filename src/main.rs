//! RIAK CLI.
//!
//! Usage:
//!   riak keygen                 — print a random 512-bit hex key
//!   riak enc <in> <out> --key <hex>   — encrypt a legacy file
//!   riak dec <in> <out> --key <hex>   — decrypt a legacy RIAK1 file
//!   riak v2enc <in> <out> --key <hex> — encrypt with experimental v0.2
//!   riak v2dec <in> <out> --key <hex> — decrypt an experimental v0.2 file
//!   riak v3enc <in> <out> --key <hex> — encrypt with experimental v0.3
//!   riak v3dec <in> <out> --key <hex> — decrypt an experimental v0.3 file
//!   `--key-file <path>` may be used instead of `--key`; on Unix it must not
//!   be group/world accessible.
//!
//! File formats:
//!   legacy RIAK1: magic "RIAK1" ‖ nonce(12) ‖ tag(16) ‖ ciphertext
//!   experimental v0.2: magic "RIAK2C" ‖ nonce(12) ‖ ciphertext ‖ tag(16)
//!   experimental v0.3: magic "RIAK3C" ‖ nonce(12) ‖ ciphertext ‖ tag(16)
//! (encrypt-then-MAC: tampered files are rejected during decryption).

#![forbid(unsafe_code)]
#![allow(deprecated)]

use riak::{v2, v3, Riak};
use std::fs;
use std::io::Write;
use std::process::exit;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const MAGIC: &[u8; 5] = b"RIAK1";
const V2_MAGIC: &[u8; 6] = b"RIAK2C";
const V2_HEADER_LEN: usize = V2_MAGIC.len() + 12;
const V3_MAGIC: &[u8; 6] = b"RIAK3C";
const V3_HEADER_LEN: usize = V3_MAGIC.len() + 12;

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

fn write_output(path: &str, data: &[u8]) {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options
        .open(path)
        .unwrap_or_else(|e| die(&format!("cannot write {path}: {e}")));
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|e| die(&format!("cannot secure permissions on {path}: {e}")));
    file.write_all(data)
        .unwrap_or_else(|e| die(&format!("cannot write {path}: {e}")));
    file.sync_all()
        .unwrap_or_else(|e| die(&format!("cannot flush {path}: {e}")));
}

fn require_file_args(args: &[String], command: &str) {
    if args.len() != 6 || !matches!(args[4].as_str(), "--key" | "--key-file") {
        die(&format!(
            "usage: riak {command} <in> <out> (--key <hex> | --key-file <path>)"
        ));
    }
}

fn key_from_args(args: &[String]) -> [u8; 64] {
    match args[4].as_str() {
        "--key" => parse_key(&args[5]),
        "--key-file" => {
            #[cfg(unix)]
            {
                let metadata = fs::metadata(&args[5]).unwrap_or_else(|e| {
                    die(&format!("cannot stat key file {}: {e}", args[5]))
                });
                if metadata.permissions().mode() & 0o077 != 0 {
                    die("key file must not be group/world accessible (use chmod 600)");
                }
            }
            let text = fs::read_to_string(&args[5])
                .unwrap_or_else(|e| die(&format!("cannot read key file {}: {e}", args[5])));
            parse_key(&text)
        }
        _ => unreachable!("argument validation happened above"),
    }
}

fn encrypt_v2_file(args: &[String]) {
    eprintln!("warning: RIAK2C v0.2 is unvalidated and rejected for production");
    require_file_args(args, "v2enc");
    let key = key_from_args(args);
    let cipher = v2::RiakV2Cipher::new(&key);
    let mut nonce = [0u8; 12];
    os_random(&mut nonce);
    let plaintext = fs::read(&args[2])
        .unwrap_or_else(|e| die(&format!("cannot read {}: {e}", args[2])));

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
    let data = fs::read(&args[2])
        .unwrap_or_else(|e| die(&format!("cannot read {}: {e}", args[2])));

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
    let plaintext = fs::read(&args[2])
        .unwrap_or_else(|e| die(&format!("cannot read {}: {e}", args[2])));

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
    let data = fs::read(&args[2])
        .unwrap_or_else(|e| die(&format!("cannot read {}: {e}", args[2])));

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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        die("usage: riak <keygen|enc|dec|v2enc|v2dec|v3enc|v3dec> [args] — see module docs");
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
        "enc" | "dec" => {
            require_file_args(&args, "enc/dec");
            let key = key_from_args(&args);
            let cipher = Riak::new(&key);
            let data = fs::read(&args[2])
                .unwrap_or_else(|e| die(&format!("cannot read {}: {e}", args[2])));

            if args[1] == "enc" {
                let mut nonce = [0u8; 12];
                os_random(&mut nonce);
                let ct = cipher.encrypt(&nonce, &data);
                let tag = cipher.mac(&ct);
                let mut out = Vec::with_capacity(5 + 12 + 16 + ct.len());
                out.extend_from_slice(MAGIC);
                out.extend_from_slice(&nonce);
                out.extend_from_slice(&tag);
                out.extend_from_slice(&ct);
                write_output(&args[3], &out);
            } else {
                if data.len() < 33 || &data[..5] != MAGIC {
                    die("not a RIAK1 file");
                }
                let nonce: [u8; 12] = data[5..17].try_into().unwrap();
                let tag: [u8; 16] = data[17..33].try_into().unwrap();
                let ct = &data[33..];
                if !cipher.verify_mac(ct, &tag) {
                    die("MAC verification FAILED — file was tampered with or wrong key");
                }
                let pt = cipher.decrypt(&nonce, ct);
                write_output(&args[3], &pt);
            }
        }
        other => die(&format!("unknown command: {other}")),
    }
}
