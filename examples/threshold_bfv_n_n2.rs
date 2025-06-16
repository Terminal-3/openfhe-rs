// examples/threshold_bfv2.rs
use openfhe::{
    ciphertext::Ciphertext, crypto_context::CryptoContext, decrypt_share::DecryptionShareVec, ffi,
    params::Params,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1) Setup BFV-RNS context with multiparty enabled using the Params wrapper
    let mut params = Params::new();
    params.set_plaintext_modulus(65537);
    // params.set_ring_dim(512); // Note: SetRingDim not available in wrapper yet
    params.set_batch_size(1);
    params.set_multiplicative_depth(0);
    // params.set_multiparty_mode(ffi::MultipartyMode::NOISE_FLOODING_MULTIPARTY);

    let mut cc = CryptoContext::new(&params);

    println!("cc: {:?}", cc);

    // Enable required features
    cc.enable_features(&[
        ffi::PKESchemeFeature::PKE,
        ffi::PKESchemeFeature::KEYSWITCH,
        ffi::PKESchemeFeature::MULTIPARTY,
    ]);

    // 2) Party A: local key-pair
    let kp1 = cc.key_gen();
    let sk1 = kp1.secret_key();
    let pk1 = kp1.public_key();

    // 3) Party B: join using A's public key
    let kp2 = cc.multiparty_key_gen(&pk1);
    let sk2 = kp2.secret_key();
    let pk2 = kp2.public_key();

    let data = vec![
        42i64, 7, 13, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101,
        103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
        197, 199, 211, 223, 227, 229,
    ];
    println!("data len → {:?}", data.len());
    println!("data → {:?}", data);

    // 4) Create plaintext using the wrapper
    let pt = cc.make_packed_plaintext(&data);

    // 5) Encrypt under the *joint* public key
    let ct = cc.encrypt(&pk2, &pt);

    // Test serialization/deserialization using the wrapper's Serialize/Deserialize traits
    let serialized_bytes = bincode::serialize(&ct)?;
    println!(
        "Serialized ciphertext len: {:.2} kB",
        serialized_bytes.len() as f64 / 1024.0
    );

    let ct_deserialized: Ciphertext = bincode::deserialize(&serialized_bytes)?;

    // Test equality using the wrapper's PartialEq implementation
    let are_equal = ct == ct_deserialized;
    println!("Are ciphertexts equal: {:?}", are_equal);

    // 6) Perform multiparty decryption using wrapper methods
    let share1 = cc.multiparty_decrypt_lead(&ct_deserialized, &sk1)?;
    let share1_bytes = bincode::serialize(&share1)?;
    println!("Share1 len → {:?} kB", share1_bytes.len() as f64 / 1024.0);
    let share1_deserialized: DecryptionShareVec = bincode::deserialize(&share1_bytes)?;

    let share2 = cc.multiparty_decrypt_main(&ct_deserialized, &sk2)?;
    let share2_bytes = bincode::serialize(&share2)?;
    println!("Share2 len → {:?} kB", share2_bytes.len() as f64 / 1024.0);
    let share2_deserialized: DecryptionShareVec = bincode::deserialize(&share2_bytes)?;

    // 7) Combine shares - we need to extend one with the other
    let mut combined_shares = share1_deserialized;
    combined_shares.extend(&share2_deserialized);

    // 8) Perform fusion to recover plaintext
    let mut recovered_pt = cc.multiparty_decrypt_fusion(&combined_shares)?;

    println!("Decrypted len → {:?}", recovered_pt.len());
    println!("Decrypted → {}", recovered_pt.get_string());

    // Set the length to match our original data length for proper comparison
    recovered_pt.set_length(data.len());
    println!("Decrypted len → {:?}", recovered_pt.len());
    println!("Decrypted → {}", recovered_pt.get_string());

    // Assert that the decrypted data matches the original
    let recovered_data = recovered_pt.get_packed_value();
    assert_eq!(data, recovered_data[..data.len()]);

    println!("✅ Threshold decryption completed successfully!");

    Ok(())
}
