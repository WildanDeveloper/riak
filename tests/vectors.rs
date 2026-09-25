#![allow(deprecated)]

// Check the Rust implementation against the Python simulator of spec v0.1.
mod vectors_data;

use riak::Riak;

#[test]
fn match_python_vectors() {
    for v in vectors_data::VECTORS {
        let cipher = Riak::from_words(v.key);
        let mut block = v.pt;
        cipher.encrypt_block(&mut block);
        assert_eq!(
            block, v.ct,
            "enkripsi gagal: {} (pt {:08x?})",
            v.name, v.pt
        );
        cipher.decrypt_block(&mut block);
        assert_eq!(block, v.pt, "dekripsi gagal: {}", v.name);
    }
}
