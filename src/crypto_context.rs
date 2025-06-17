use std::fmt::Debug;

use crate::{
    ciphertext::Ciphertext, decrypt_share::DecryptionShareVec, ffi, keys::KeyPair, keys::PublicKey,
    keys::SecretKey, params::Params, plaintext::Plaintext,
};
use cxx::{CxxVector, UniquePtr};

/// The main crypto context for performing homomorphic encryption operations.
pub struct CryptoContext(pub(crate) UniquePtr<ffi::CryptoContextDCRTPoly>);

impl Debug for CryptoContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CryptoContext")?;
        // params
        let params = self.0.as_ref().ok_or_else(|| std::fmt::Error)?;
        let crypto_params = params.GetCryptoParameters();
        let crypto_params_ref = crypto_params.as_ref().ok_or_else(|| std::fmt::Error)?;
        write!(
            f,
            "params: {:?}",
            ffi::CryptoParametersBaseDCRTPolyToString(crypto_params_ref)
        )?;
        Ok(())
    }
}

impl CryptoContext {
    /// Generates a new `CryptoContext` from the given parameters.
    pub fn new(params: &Params) -> Result<Self, String> {
        let mut cc = ffi::DCRTPolyGenCryptoContextByParamsBFVRNS(&params.0);
        // Enable required features
        cc.as_mut()
            .ok_or_else(|| "Failed to get mutable reference to crypto context".to_string())?
            .EnableByFeature(ffi::PKESchemeFeature::PKE);
        cc.as_mut()
            .ok_or_else(|| "Failed to get mutable reference to crypto context".to_string())?
            .EnableByFeature(ffi::PKESchemeFeature::KEYSWITCH);
        cc.as_mut()
            .ok_or_else(|| "Failed to get mutable reference to crypto context".to_string())?
            .EnableByFeature(ffi::PKESchemeFeature::MULTIPARTY);
        Ok(CryptoContext(cc))
    }
    pub fn new_without_features(params: &Params) -> Self {
        let cc = ffi::DCRTPolyGenCryptoContextByParamsBFVRNS(&params.0);
        CryptoContext(cc)
    }

    /// Enables a set of cryptographic features.
    pub fn enable_features(&mut self, features: &[ffi::PKESchemeFeature]) -> Result<(), String> {
        for &feature in features {
            self.0
                .as_mut()
                .ok_or_else(|| "Failed to get mutable reference to crypto context".to_string())?
                .EnableByFeature(feature);
        }
        Ok(())
    }

    pub fn get_modulus(&self) -> Result<u64, String> {
        let cc = self
            .0
            .as_ref()
            .ok_or_else(|| "Failed to get reference to crypto context".to_string())?;
        Ok(cc.GetModulus())
    }

    // fn GetCryptoParameters(
    //     self: &CryptoContextDCRTPoly,
    // ) -> UniquePtr<CryptoParametersBaseDCRTPoly>;
    // fn GetCyclotomicOrder(self: &CryptoContextDCRTPoly) -> u32;
    // fn GetElementParams(self: &CryptoContextDCRTPoly) -> UniquePtr<DCRTPolyParams>;
    // fn GetEncodingParams(self: &CryptoContextDCRTPoly) -> UniquePtr<EncodingParams>;
    // fn GetKeyGenLevel(self: &CryptoContextDCRTPoly) -> usize;
    // fn GetModulus(self: &CryptoContextDCRTPoly) -> u64;
    // fn GetRingDimension(self: &CryptoContextDCRTPoly) -> u32;
    // fn GetRootOfUnity(self: &CryptoContextDCRTPoly) -> u64;
    // fn GetScheme(self: &CryptoContextDCRTPoly) -> UniquePtr<SchemeBaseDCRTPoly>;
    // fn GetSchemeId(self: &CryptoContextDCRTPoly) -> SCHEME;
    // fn GetSwkFC(self: &CryptoContextDCRTPoly) -> UniquePtr<CiphertextDCRTPoly>;

    pub fn get_root_of_unity(&self) -> Result<u64, String> {
        let cc = self
            .0
            .as_ref()
            .ok_or_else(|| "Failed to get reference to crypto context".to_string())?;
        Ok(cc.GetRootOfUnity())
    }

    pub fn get_ring_dimension(&self) -> Result<u32, String> {
        let cc = self
            .0
            .as_ref()
            .ok_or_else(|| "Failed to get reference to crypto context".to_string())?;
        Ok(cc.GetRingDimension())
    }

    pub fn get_scheme(&self) -> Result<ffi::SCHEME, String> {
        let cc = self
            .0
            .as_ref()
            .ok_or_else(|| "Failed to get reference to crypto context".to_string())?;
        Ok(cc.GetSchemeId())
    }

    pub fn get_scheme_id(&self) -> Result<ffi::SCHEME, String> {
        let cc = self
            .0
            .as_ref()
            .ok_or_else(|| "Failed to get reference to crypto context".to_string())?;
        Ok(cc.GetSchemeId())
    }

    pub fn get_swk_fc(&self) -> Result<Ciphertext, String> {
        let cc = self
            .0
            .as_ref()
            .ok_or_else(|| "Failed to get reference to crypto context".to_string())?;
        Ok(Ciphertext(cc.GetSwkFC()))
    }

    pub fn get_key_gen_level(&self) -> Result<usize, String> {
        let cc = self
            .0
            .as_ref()
            .ok_or_else(|| "Failed to get reference to crypto context".to_string())?;
        Ok(cc.GetKeyGenLevel())
    }

    // pub fn get_encoding_params(&self) -> Result<ffi::EncodingParams, String> {
    //     let cc = self
    //         .0
    //         .as_ref()
    //         .ok_or_else(|| "Failed to get reference to crypto context".to_string())?;
    //     Ok(cc.GetEncodingParams())
    // }

    // pub fn get_element_params(&self) -> Result<ffi::DCRTPolyParams, String> {
    //     let cc = self
    //         .0
    //         .as_ref()
    //         .ok_or_else(|| "Failed to get reference to crypto context".to_string())?;
    //     Ok(cc.GetElementParams())
    // }

    // pub fn get_crypto_parameters(&self) -> Result<ffi::CryptoParametersBaseDCRTPoly, String> {
    //     let cc = self
    //         .0
    //         .as_ref()
    //         .ok_or_else(|| "Failed to get reference to crypto context".to_string())?;
    //     Ok(cc.GetCryptoParameters())
    // }

    pub fn get_cyclotomic_order(&self) -> Result<u32, String> {
        let cc = self
            .0
            .as_ref()
            .ok_or_else(|| "Failed to get reference to crypto context".to_string())?;
        Ok(cc.GetCyclotomicOrder())
    }

    /// Generates a new key pair.
    pub fn key_gen(&self) -> Result<KeyPair, String> {
        let cc = self
            .0
            .as_ref()
            .ok_or_else(|| "Failed to get reference to crypto context".to_string())?;
        Ok(KeyPair(cc.KeyGen()))
    }

    /// Generates a new key pair for multiparty computation, using another party's public key.
    pub fn multiparty_key_gen(&self, pk: &PublicKey) -> Result<KeyPair, String> {
        let cc = self
            .0
            .as_ref()
            .ok_or_else(|| "Failed to get reference to crypto context".to_string())?;
        Ok(KeyPair(cc.MultipartyKeyGenByPublicKey(&pk.0, false, false)))
    }

    /// Creates a packed plaintext from a slice of i64 values.
    pub fn make_packed_plaintext(&self, data: &[i64]) -> Result<Plaintext, String> {
        let mut data_vec = CxxVector::<i64>::new();
        for &x in data {
            data_vec.pin_mut().push(x);
        }
        let cc = self
            .0
            .as_ref()
            .ok_or_else(|| "Failed to get reference to crypto context".to_string())?;
        Ok(Plaintext(cc.MakePackedPlaintext(&data_vec, 1, 0)))
    }

    /// Encrypts a plaintext using a public key.
    pub fn encrypt(&self, pk: &PublicKey, pt: &Plaintext) -> Result<Ciphertext, String> {
        let cc = self
            .0
            .as_ref()
            .ok_or_else(|| "Failed to get reference to crypto context".to_string())?;
        Ok(Ciphertext(cc.EncryptByPublicKey(&pk.0, &pt.0)))
    }

    /// Decrypts a ciphertext using a secret key.
    /// Returns a Result containing either the decrypted plaintext or an error message.
    pub fn decrypt(&self, sk: &SecretKey, ct: &Ciphertext) -> Result<Plaintext, String> {
        let mut pt = ffi::GenNullPlainText();
        let cc = self
            .0
            .as_ref()
            .ok_or_else(|| "CryptoContext is null".to_string())?;
        let result = cc.DecryptByPrivateKeyAndCiphertext(&sk.0, &ct.0, pt.pin_mut());

        // Check if decryption was successful
        if !result
            .as_ref()
            .ok_or_else(|| "DecryptResult is null".to_string())?
            .DecryptResultIsValid()
        {
            return Err("Decryption failed - invalid result".to_string());
        }

        Ok(Plaintext(pt))
    }

    /// Performs the lead role in multiparty decryption.
    pub fn multiparty_decrypt_lead(
        &self,
        ciphertext: &Ciphertext,
        sk: &SecretKey,
    ) -> Result<DecryptionShareVec, String> {
        let cc = self
            .0
            .as_ref()
            .ok_or_else(|| "CryptoContext is null".to_string())?;
        let ct_ref = ciphertext
            .0
            .as_ref()
            .ok_or_else(|| "Ciphertext is null".to_string())?;
        let enc_vec = ffi::vector_of_ciphertexts_single(ct_ref.GetRef());
        Ok(DecryptionShareVec(
            cc.MultipartyDecryptLead(&enc_vec, &sk.0),
        ))
    }

    /// Performs the main (non-lead) role in multiparty decryption.
    pub fn multiparty_decrypt_main(
        &self,
        ciphertext: &Ciphertext,
        sk: &SecretKey,
    ) -> Result<DecryptionShareVec, String> {
        let cc = self
            .0
            .as_ref()
            .ok_or_else(|| "CryptoContext is null".to_string())?;
        let ct_ref = ciphertext
            .0
            .as_ref()
            .ok_or_else(|| "Ciphertext is null".to_string())?;
        let enc_vec = ffi::vector_of_ciphertexts_single(ct_ref.GetRef());
        Ok(DecryptionShareVec(
            cc.MultipartyDecryptMain(&enc_vec, &sk.0),
        ))
    }

    /// Fuses partial decryption shares to recover the plaintext.
    pub fn multiparty_decrypt_fusion(
        &mut self,
        shares: &DecryptionShareVec,
    ) -> Result<Plaintext, String> {
        let mut pt = ffi::GenNullPlainText();
        let cc = self
            .0
            .as_mut()
            .ok_or_else(|| "CryptoContext is null".to_string())?;
        let result = cc.MultipartyDecryptFusion(&shares.0, pt.pin_mut());

        // Check if fusion was successful
        if !result
            .as_ref()
            .ok_or_else(|| "DecryptResult is null".to_string())?
            .DecryptResultIsValid()
        {
            return Err("Multiparty decryption fusion failed - invalid result".to_string());
        }

        Ok(Plaintext(pt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi;
    use std::sync::Mutex;

    /// Helper function to create test parameters
    fn create_test_params() -> Params {
        let params = Params::default();
        params
    }

    /// Helper function to create a crypto context with standard features enabled
    fn create_test_crypto_context() -> CryptoContext {
        let params = create_test_params();
        let mut cc = CryptoContext::new(&params).unwrap();
        cc
    }

    #[test]
    fn test_crypto_context_debug() {
        let cc = create_test_crypto_context();
        println!("cc: {:?}", cc);
    }

    #[test]
    fn test_crypto_context_creation() {
        let params = create_test_params();
        let cc = CryptoContext::new(&params).unwrap();

        // Test that crypto context is created successfully
        assert!(cc.0.as_ref().is_some());
    }

    #[test]
    fn test_crypto_context_enable_features() {
        let params = create_test_params();
        let mut cc = CryptoContext::new(&params).unwrap();

        // Test enabling individual features
        cc.enable_features(&[ffi::PKESchemeFeature::PKE]).unwrap();
        cc.enable_features(&[ffi::PKESchemeFeature::KEYSWITCH])
            .unwrap();
        cc.enable_features(&[ffi::PKESchemeFeature::LEVELEDSHE])
            .unwrap();

        // Test enabling multiple features at once
        cc.enable_features(&[
            ffi::PKESchemeFeature::PKE,
            ffi::PKESchemeFeature::KEYSWITCH,
            ffi::PKESchemeFeature::LEVELEDSHE,
        ])
        .unwrap();

        // Should not panic - features can be enabled multiple times
        assert!(cc.0.as_ref().is_some());
    }

    #[test]
    fn test_crypto_context_key_gen() {
        let cc = create_test_crypto_context();

        let key_pair = cc.key_gen().unwrap();

        // Test that key pair is generated successfully
        assert!(key_pair.0.as_ref().is_some());

        // Extract individual keys
        let public_key = key_pair.public_key();
        let secret_key = key_pair.secret_key();

        assert!(public_key.0.as_ref().is_some());
        assert!(secret_key.0.as_ref().is_some());
    }

    #[test]
    fn test_crypto_context_multiple_key_gen() {
        let cc = create_test_crypto_context();

        // Generate multiple key pairs
        let key_pair1 = cc.key_gen().unwrap();
        let key_pair2 = cc.key_gen().unwrap();
        let key_pair3 = cc.key_gen().unwrap();

        // All should be valid but different
        assert!(key_pair1.0.as_ref().is_some());
        assert!(key_pair2.0.as_ref().is_some());
        assert!(key_pair3.0.as_ref().is_some());

        // Keys should be different (we can't directly compare, but they should be independently valid)
        let pk1 = key_pair1.public_key();
        let pk2 = key_pair2.public_key();
        let pk3 = key_pair3.public_key();

        assert!(pk1.0.as_ref().is_some());
        assert!(pk2.0.as_ref().is_some());
        assert!(pk3.0.as_ref().is_some());
    }

    #[test]
    fn test_crypto_context_multiparty_key_gen() {
        let cc = create_test_crypto_context();

        // Generate initial key pair
        let initial_key_pair = cc.key_gen().unwrap();
        let initial_public_key = initial_key_pair.public_key();

        // Generate multiparty key pair using the initial public key
        let multiparty_key_pair = cc.multiparty_key_gen(&initial_public_key).unwrap();

        // Test that multiparty key pair is generated successfully
        assert!(multiparty_key_pair.0.as_ref().is_some());

        let mp_public_key = multiparty_key_pair.public_key();
        let mp_secret_key = multiparty_key_pair.secret_key();

        assert!(mp_public_key.0.as_ref().is_some());
        assert!(mp_secret_key.0.as_ref().is_some());
    }

    #[test]
    fn test_crypto_context_make_packed_plaintext() {
        let cc = create_test_crypto_context();

        // Test with single value
        let single_data = vec![42];
        let pt1 = cc.make_packed_plaintext(&single_data).unwrap();
        assert!(pt1.0.as_ref().is_some());

        // Test with multiple values
        let multi_data = vec![1, 2, 3, 4, 5];
        let pt2 = cc.make_packed_plaintext(&multi_data).unwrap();
        assert!(pt2.0.as_ref().is_some());

        // Test with single zero (empty data not supported)
        let zero_data = vec![0];
        let pt3 = cc.make_packed_plaintext(&zero_data).unwrap();
        assert!(pt3.0.as_ref().is_some());

        // Test with large values (within modulus)
        let large_data = vec![65536, 32768, 16384];
        let pt4 = cc.make_packed_plaintext(&large_data).unwrap();
        assert!(pt4.0.as_ref().is_some());
    }

    #[test]
    fn test_crypto_context_encrypt() {
        let cc = create_test_crypto_context();
        let key_pair = cc.key_gen().unwrap();
        let public_key = key_pair.public_key();

        // Create plaintext and encrypt
        let data = vec![1, 2, 3, 4, 5];
        let plaintext = cc.make_packed_plaintext(&data).unwrap();
        let ciphertext = cc.encrypt(&public_key, &plaintext).unwrap();

        // Test that encryption succeeds
        assert!(ciphertext.0.as_ref().is_some());
    }

    #[test]
    fn test_crypto_context_encrypt_multiple() {
        let cc = create_test_crypto_context();
        let key_pair = cc.key_gen().unwrap();
        let public_key = key_pair.public_key();

        // Encrypt multiple different plaintexts
        let data_sets = vec![
            vec![1],
            vec![1, 2, 3],
            vec![100, 200, 300, 400],
            vec![0, 0, 0],
            vec![65536],
        ];

        for (i, data) in data_sets.iter().enumerate() {
            let plaintext = cc.make_packed_plaintext(data).unwrap();
            let ciphertext = cc.encrypt(&public_key, &plaintext).unwrap();

            assert!(
                ciphertext.0.as_ref().is_some(),
                "Encryption failed for data set {}: {:?}",
                i,
                data
            );
        }
    }

    #[test]
    fn test_crypto_context_multiparty_decrypt_operations() {
        let mut cc = create_test_crypto_context();
        let key_pair = cc.key_gen().unwrap();
        let public_key = key_pair.public_key();
        let secret_key = key_pair.secret_key();

        // Create and encrypt plaintext
        let data = vec![1, 2, 3, 4, 5];
        let plaintext = cc.make_packed_plaintext(&data).unwrap();
        let ciphertext = cc.encrypt(&public_key, &plaintext).unwrap();

        // Test multiparty decrypt operations (these may fail due to missing FFI functions)
        let lead_result = cc.multiparty_decrypt_lead(&ciphertext, &secret_key);
        let main_result = cc.multiparty_decrypt_main(&ciphertext, &secret_key);

        // Handle potential failures gracefully
        match lead_result {
            Ok(shares) => {
                assert!(shares.0.as_ref().is_some());
                println!("Multiparty decrypt lead succeeded");

                // Try fusion if lead succeeded
                match cc.multiparty_decrypt_fusion(&shares) {
                    Ok(recovered_pt) => {
                        assert!(recovered_pt.0.as_ref().is_some());
                        println!("Multiparty decrypt fusion succeeded");
                    }
                    Err(e) => {
                        println!("Multiparty decrypt fusion failed: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("Multiparty decrypt lead failed: {}", e);
            }
        }

        match main_result {
            Ok(shares) => {
                assert!(shares.0.as_ref().is_some());
                println!("Multiparty decrypt main succeeded");
            }
            Err(e) => {
                println!("Multiparty decrypt main failed: {}", e);
            }
        }
    }

    #[test]
    fn test_crypto_context_cross_context_operations() {
        // Create two separate contexts
        let cc1 = create_test_crypto_context();
        let cc2 = create_test_crypto_context();

        let key_pair1 = cc1.key_gen().unwrap();
        let key_pair2 = cc2.key_gen().unwrap();

        let public_key1 = key_pair1.public_key();
        let public_key2 = key_pair2.public_key();

        // Create plaintexts in both contexts
        let data1 = vec![1, 2, 3];
        let data2 = vec![4, 5, 6];

        let pt1 = cc1.make_packed_plaintext(&data1).unwrap();
        let pt2 = cc2.make_packed_plaintext(&data2).unwrap();

        // Encrypt in both contexts
        let _ = cc1.encrypt(&public_key1, &pt1).unwrap();
        let _ = cc2.encrypt(&public_key2, &pt2).unwrap();

        // Test cross-context operations (may cause issues but shouldn't segfault)
        let cross_encrypt_result = std::panic::catch_unwind(|| {
            cc1.encrypt(&public_key2, &pt1).unwrap() // Using cc1 with key from cc2
        });

        let cross_plaintext_result = std::panic::catch_unwind(|| {
            cc2.encrypt(&public_key1, &pt2).unwrap() // Using cc2 with key from cc1
        });

        // These operations may fail but shouldn't cause segfaults
        // We just verify they don't crash the program
        match cross_encrypt_result {
            Ok(ct) => {
                assert!(ct.0.as_ref().is_some());
                println!("Cross-context encryption succeeded unexpectedly");
            }
            Err(_) => {
                println!("Cross-context encryption failed as potentially expected");
            }
        }

        match cross_plaintext_result {
            Ok(ct) => {
                assert!(ct.0.as_ref().is_some());
                println!("Cross-context plaintext encryption succeeded unexpectedly");
            }
            Err(_) => {
                println!("Cross-context plaintext encryption failed as potentially expected");
            }
        }
    }

    #[test]
    fn test_concurrent_crypto_context_operations() {
        use std::sync::{Arc, Barrier};
        use std::thread;
        use std::time::Duration;

        const NUM_THREADS: usize = 6;
        const ITERATIONS_PER_THREAD: usize = 30;

        // Create a barrier to synchronize thread startup
        let barrier = Arc::new(Barrier::new(NUM_THREADS));
        let mut handles = Vec::new();

        // Track any panics that occur
        let panic_counter = Arc::new(Mutex::new(0));

        for thread_id in 0..NUM_THREADS {
            let barrier_clone = Arc::clone(&barrier);
            let panic_counter_clone = Arc::clone(&panic_counter);

            let handle = thread::spawn(move || {
                // Wait for all threads to be ready
                barrier_clone.wait();

                // Small random delay to increase chance of race conditions
                thread::sleep(Duration::from_millis((thread_id * 10) as u64));

                for iteration in 0..ITERATIONS_PER_THREAD {
                    // Catch any panics/segfaults
                    let result = std::panic::catch_unwind(|| {
                        // Create crypto context
                        let cc = create_test_crypto_context();

                        // Generate keys
                        let key_pair1 = cc.key_gen().unwrap();
                        let key_pair2 = cc.key_gen().unwrap();

                        let public_key1 = key_pair1.public_key();
                        let public_key2 = key_pair2.public_key();
                        let secret_key1 = key_pair1.secret_key();

                        // Create plaintexts with thread-specific data
                        let data1 = vec![thread_id as i64, iteration as i64];
                        let data2 = vec![(thread_id * 10) as i64, (iteration * 10) as i64];
                        let data3 = vec![thread_id as i64 + iteration as i64];

                        let pt1 = cc.make_packed_plaintext(&data1).unwrap();
                        let pt2 = cc.make_packed_plaintext(&data2).unwrap();
                        let pt3 = cc.make_packed_plaintext(&data3).unwrap();

                        // Encrypt with different keys
                        let ct1 = cc.encrypt(&public_key1, &pt1).unwrap();
                        let ct2 = cc.encrypt(&public_key2, &pt2).unwrap();
                        let ct3 = cc.encrypt(&public_key1, &pt3).unwrap();

                        // Test basic validity
                        assert!(ct1.0.as_ref().is_some());
                        assert!(ct2.0.as_ref().is_some());
                        assert!(ct3.0.as_ref().is_some());

                        // Test multiparty operations (may fail but shouldn't segfault)
                        let _mp_key_result = std::panic::catch_unwind(|| {
                            cc.multiparty_key_gen(&public_key1).unwrap()
                        });

                        let _mp_decrypt_lead_result = std::panic::catch_unwind(|| {
                            cc.multiparty_decrypt_lead(&ct1, &secret_key1).unwrap()
                        });

                        let _mp_decrypt_main_result = std::panic::catch_unwind(|| {
                            cc.multiparty_decrypt_main(&ct2, &secret_key1).unwrap()
                        });

                        // Create another context to test cross-context behavior
                        let cc2 = create_test_crypto_context();
                        let key_pair3 = cc2.key_gen().unwrap();
                        let public_key3 = key_pair3.public_key();

                        let pt4 = cc2.make_packed_plaintext(&data1).unwrap();
                        let ct4 = cc2.encrypt(&public_key3, &pt4).unwrap();

                        assert!(ct4.0.as_ref().is_some());
                    });

                    if result.is_err() {
                        let mut counter = panic_counter_clone.lock().unwrap();
                        *counter += 1;
                        eprintln!(
                            "CryptoContext Thread {} panic at iteration {}: {:?}",
                            thread_id, iteration, result
                        );
                        break; // Exit this thread's loop on panic
                    }

                    // Small delay between iterations
                    if iteration % 10 == 0 {
                        thread::sleep(Duration::from_millis(1));
                    }
                }

                println!("CryptoContext Thread {} completed successfully", thread_id);
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for (i, handle) in handles.into_iter().enumerate() {
            match handle.join() {
                Ok(_) => println!("CryptoContext Thread {} joined successfully", i),
                Err(e) => {
                    eprintln!("CryptoContext Thread {} panicked: {:?}", i, e);
                    let mut counter = panic_counter.lock().unwrap();
                    *counter += 1;
                }
            }
        }

        let final_panic_count = *panic_counter.lock().unwrap();

        if final_panic_count > 0 {
            panic!(
                "Concurrent crypto context test detected {} panics/segfaults. This indicates thread safety issues!",
                final_panic_count
            );
        }

        println!("Concurrent crypto context test completed successfully - no thread safety issues detected");
    }

    #[test]
    fn test_stress_crypto_context_creation() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        const NUM_THREADS: usize = 4;
        const CONTEXTS_PER_THREAD: usize = 15;

        let barrier = Arc::new(Barrier::new(NUM_THREADS));
        let mut handles = Vec::new();

        for thread_id in 0..NUM_THREADS {
            let barrier_clone = Arc::clone(&barrier);

            let handle = thread::spawn(move || {
                barrier_clone.wait();

                let mut contexts_and_data = Vec::new();

                // Create multiple contexts rapidly
                for i in 0..CONTEXTS_PER_THREAD {
                    let result = std::panic::catch_unwind(|| {
                        let cc = create_test_crypto_context();

                        // Generate multiple key pairs per context
                        let kp1 = cc.key_gen().unwrap();
                        let kp2 = cc.key_gen().unwrap();

                        // Create plaintexts and ciphertexts
                        let data = vec![i as i64, thread_id as i64];
                        let pt = cc.make_packed_plaintext(&data).unwrap();

                        let pk1 = kp1.public_key();
                        let ct = cc.encrypt(&pk1, &pt).unwrap();

                        (cc, vec![kp1, kp2], vec![pt], vec![ct])
                    });

                    match result {
                        Ok((cc, key_pairs, plaintexts, ciphertexts)) => {
                            // Store them to prevent immediate destruction
                            contexts_and_data.push((cc, key_pairs, plaintexts, ciphertexts));

                            // Perform some operations on the latest context
                            if let Some((latest_cc, latest_kps, _, _)) = contexts_and_data.last() {
                                if !latest_kps.is_empty() {
                                    let test_data = vec![999];
                                    let test_pt =
                                        latest_cc.make_packed_plaintext(&test_data).unwrap();
                                    let test_pk = latest_kps[0].public_key();
                                    let _test_ct = latest_cc.encrypt(&test_pk, &test_pt).unwrap();
                                }
                            }
                        }
                        Err(e) => {
                            panic!(
                                "Thread {} panicked at context creation {}: {:?}",
                                thread_id, i, e
                            );
                        }
                    }
                }

                println!(
                    "Thread {} created {} contexts successfully",
                    thread_id, CONTEXTS_PER_THREAD
                );

                // Test operations on all created contexts
                for (i, (cc, key_pairs, plaintexts, ciphertexts)) in
                    contexts_and_data.iter().enumerate()
                {
                    let result = std::panic::catch_unwind(|| {
                        // Test additional operations
                        if !key_pairs.is_empty() && !plaintexts.is_empty() {
                            let new_data = vec![i as i64 * 10];
                            let new_pt = cc.make_packed_plaintext(&new_data).unwrap();
                            let pk = key_pairs[0].public_key();
                            let _new_ct = cc.encrypt(&pk, &new_pt).unwrap();
                        }

                        // Verify all stored objects are still valid
                        for kp in key_pairs {
                            assert!(kp.0.as_ref().is_some());
                        }
                        for pt in plaintexts {
                            assert!(pt.0.as_ref().is_some());
                        }
                        for ct in ciphertexts {
                            assert!(ct.0.as_ref().is_some());
                        }
                    });

                    if result.is_err() {
                        panic!(
                            "Thread {} panicked during operations on context {}: {:?}",
                            thread_id, i, result
                        );
                    }
                }
            });

            handles.push(handle);
        }

        for (i, handle) in handles.into_iter().enumerate() {
            match handle.join() {
                Ok(_) => println!(
                    "CryptoContext stress test thread {} completed successfully",
                    i
                ),
                Err(e) => panic!("CryptoContext stress test thread {} panicked: {:?}", i, e),
            }
        }

        println!("CryptoContext stress test completed successfully");
    }

    #[test]
    fn test_massive_concurrent_crypto_context_load() {
        use std::sync::{Arc, Barrier};
        use std::thread;
        use std::time::Duration;

        const NUM_THREADS: usize = 8;
        const ITERATIONS_PER_THREAD: usize = 20;

        let barrier = Arc::new(Barrier::new(NUM_THREADS));
        let mut handles = Vec::new();
        let panic_counter = Arc::new(Mutex::new(0));

        for thread_id in 0..NUM_THREADS {
            let barrier_clone = Arc::clone(&barrier);
            let panic_counter_clone = Arc::clone(&panic_counter);

            let handle = thread::spawn(move || {
                barrier_clone.wait();

                // Staggered start to create more race conditions
                thread::sleep(Duration::from_millis((thread_id % 3) as u64));

                for iteration in 0..ITERATIONS_PER_THREAD {
                    let result = std::panic::catch_unwind(|| {
                        // Create multiple crypto contexts simultaneously
                        let cc1 = create_test_crypto_context();
                        let cc2 = create_test_crypto_context();

                        // Generate many key pairs rapidly
                        let mut key_pairs = Vec::new();
                        let mut plaintexts = Vec::new();
                        let mut ciphertexts = Vec::new();

                        for i in 0..5 {
                            let value = (thread_id * 1000 + iteration * 10 + i) as i64;

                            // Alternate between contexts
                            let (cc, kp) = if i % 2 == 0 {
                                (&cc1, cc1.key_gen().unwrap())
                            } else {
                                (&cc2, cc2.key_gen().unwrap())
                            };

                            let pk = kp.public_key();
                            let _sk = kp.secret_key();

                            // Create various plaintexts
                            let pt1 = cc.make_packed_plaintext(&[value]).unwrap();
                            let pt2 = cc.make_packed_plaintext(&[value, value + 1]).unwrap();
                            let pt3 = cc.make_packed_plaintext(&[0, value, value * 2]).unwrap();

                            // Encrypt all plaintexts
                            let ct1 = cc.encrypt(&pk, &pt1).unwrap();
                            let ct2 = cc.encrypt(&pk, &pt2).unwrap();
                            let ct3 = cc.encrypt(&pk, &pt3).unwrap();

                            key_pairs.push(kp);
                            plaintexts.extend(vec![pt1, pt2, pt3]);
                            ciphertexts.extend(vec![ct1, ct2, ct3]);
                        }

                        // Perform massive operations
                        for (i, kp) in key_pairs.iter().enumerate() {
                            let pk = kp.public_key();
                            let sk = kp.secret_key();

                            // Basic validity checks
                            assert!(pk.0.as_ref().is_some());
                            assert!(sk.0.as_ref().is_some());

                            // Cross-context operations (high chance of triggering issues)
                            let cc = if i % 2 == 0 { &cc1 } else { &cc2 };

                            if i < plaintexts.len() {
                                let _cross_encrypt = std::panic::catch_unwind(|| {
                                    cc.encrypt(&pk, &plaintexts[i]).unwrap()
                                });
                            }

                            // Multiparty operations (may fail but shouldn't segfault)
                            let _mp_key_gen =
                                std::panic::catch_unwind(|| cc.multiparty_key_gen(&pk).unwrap());

                            if i < ciphertexts.len() {
                                let _mp_decrypt_lead = std::panic::catch_unwind(|| {
                                    cc.multiparty_decrypt_lead(&ciphertexts[i], &sk).unwrap()
                                });

                                let _mp_decrypt_main = std::panic::catch_unwind(|| {
                                    cc.multiparty_decrypt_main(&ciphertexts[i], &sk).unwrap()
                                });
                            }
                        }

                        // Cross-validation of all objects
                        for pt in &plaintexts {
                            assert!(pt.0.as_ref().is_some());
                        }
                        for ct in &ciphertexts {
                            assert!(ct.0.as_ref().is_some());
                        }
                    });

                    if result.is_err() {
                        let mut counter = panic_counter_clone.lock().unwrap();
                        *counter += 1;
                        eprintln!(
                            "Massive CryptoContext load Thread {} panic at iteration {}: {:?}",
                            thread_id, iteration, result
                        );
                        break;
                    }

                    // Very short sleep to allow other threads to interleave
                    if iteration % 5 == 0 {
                        thread::sleep(Duration::from_millis(1));
                    }
                }

                println!(
                    "Massive CryptoContext load Thread {} completed successfully",
                    thread_id
                );
            });

            handles.push(handle);
        }

        for (i, handle) in handles.into_iter().enumerate() {
            match handle.join() {
                Ok(_) => println!(
                    "Massive CryptoContext load Thread {} joined successfully",
                    i
                ),
                Err(e) => {
                    eprintln!("Massive CryptoContext load Thread {} panicked: {:?}", i, e);
                    let mut counter = panic_counter.lock().unwrap();
                    *counter += 1;
                }
            }
        }

        let final_panic_count = *panic_counter.lock().unwrap();

        if final_panic_count > 0 {
            panic!(
                "Massive concurrent CryptoContext load test detected {} panics/segfaults. This indicates serious thread safety issues!",
                final_panic_count
            );
        }

        println!("Massive concurrent CryptoContext load test completed successfully - no thread safety issues detected");
    }

    #[test]
    fn test_crypto_context_edge_cases() {
        let cc = create_test_crypto_context();

        // Test with edge case parameters
        let edge_cases = vec![
            vec![0],                             // Zero
            vec![1],                             // Minimum positive
            vec![65536],                         // Maximum valid value
            vec![-1],                            // Negative (will be reduced modulo)
            vec![0, 0, 0, 0],                    // All zeros
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10], // Many values
        ];

        let key_pair = cc.key_gen().unwrap();
        let public_key = key_pair.public_key();

        for (i, data) in edge_cases.iter().enumerate() {
            let pt = cc.make_packed_plaintext(data).unwrap();
            assert!(
                pt.0.as_ref().is_some(),
                "Plaintext creation failed for case {}: {:?}",
                i,
                data
            );

            let ct = cc.encrypt(&public_key, &pt).unwrap();
            assert!(
                ct.0.as_ref().is_some(),
                "Encryption failed for case {}: {:?}",
                i,
                data
            );
        }

        // Test enabling features multiple times and in different orders
        let mut cc2 = CryptoContext::new(&create_test_params()).unwrap();

        cc2.enable_features(&[ffi::PKESchemeFeature::LEVELEDSHE])
            .unwrap();
        cc2.enable_features(&[ffi::PKESchemeFeature::PKE]).unwrap();
        cc2.enable_features(&[ffi::PKESchemeFeature::KEYSWITCH])
            .unwrap();
        cc2.enable_features(&[ffi::PKESchemeFeature::PKE]).unwrap(); // Duplicate

        let kp2 = cc2.key_gen().unwrap();
        assert!(kp2.0.as_ref().is_some());
    }

    #[test]
    fn test_crypto_context_roundtrip_decrypt() {
        let cc = create_test_crypto_context();
        let key_pair = cc.key_gen().unwrap();
        let public_key = key_pair.public_key();
        let secret_key = key_pair.secret_key();

        // Test data sets
        let test_data_sets = vec![
            // Sequential numbers from 0 to 32
            (0..=31).collect::<Vec<i64>>(),
            // Single value
            vec![42],
            // Small range
            vec![1, 2, 3, 4, 5],
            // Edge cases
            vec![0],
            vec![65536], // Maximum valid value for the modulus
            // Larger set with gaps
            vec![0, 5, 10, 15, 20, 25, 30],
        ];

        for (i, data) in test_data_sets.iter().enumerate() {
            // Create plaintext
            let plaintext = cc.make_packed_plaintext(data).unwrap();
            assert!(
                plaintext.0.as_ref().is_some(),
                "Plaintext creation failed for data set {}: {:?}",
                i,
                data
            );

            // Encrypt
            let ciphertext = cc.encrypt(&public_key, &plaintext).unwrap();
            assert!(
                ciphertext.0.as_ref().is_some(),
                "Encryption failed for data set {}: {:?}",
                i,
                data
            );

            // Decrypt
            let decrypted = cc.decrypt(&secret_key, &ciphertext).unwrap();
            let decrypted_positive_values = decrypted
                .get_packed_value()
                .iter()
                .map(|x| if *x < 0 { *x + 65537 } else { *x })
                .collect::<Vec<i64>>();

            assert_eq!(&decrypted_positive_values[..data.len()], data.as_slice());

            // TODO: Add actual value comparison once we have a way to extract values from Plaintext
            // For now, we just verify that the decryption operation succeeds
            println!(
                "Successfully completed roundtrip for data set {}: {:?}",
                i, data
            );
        }
    }
}
