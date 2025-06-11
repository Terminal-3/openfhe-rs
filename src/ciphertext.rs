use crate::ffi;
use cxx::{CxxVector, UniquePtr};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A wrapper for a homomorphic ciphertext.
///
/// This struct provides safe methods and implements standard traits for easier handling.
pub struct Ciphertext(pub(crate) UniquePtr<ffi::CiphertextDCRTPoly>);

impl Clone for Ciphertext {
    /// Clones the ciphertext using the underlying C++ clone function.
    fn clone(&self) -> Self {
        Ciphertext(ffi::DCRTPolyCloneCiphertext(&self.0))
    }
}

impl std::fmt::Debug for Ciphertext {
    /// Formats the ciphertext by showing its serialized size, avoiding printing large objects.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out_bytes = CxxVector::<u8>::new();
        ffi::DCRTPolySerializeCiphertextToBytes(self.0.as_ref().unwrap(), out_bytes.pin_mut());
        f.debug_struct("Ciphertext")
            .field("len_bytes", &out_bytes.len())
            .finish()
    }
}

impl PartialEq for Ciphertext {
    /// Checks for equality by calling the underlying C++ comparison function.
    fn eq(&self, other: &Self) -> bool {
        ffi::AreCiphertextsEqual(&self.0, &other.0)
    }
}
impl Eq for Ciphertext {}

impl Serialize for Ciphertext {
    /// Serializes the ciphertext into a byte vector.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut out_bytes = CxxVector::<u8>::new();
        ffi::DCRTPolySerializeCiphertextToBytes(self.0.as_ref().unwrap(), out_bytes.pin_mut());
        serializer.serialize_bytes(out_bytes.as_slice())
    }
}

impl<'de> Deserialize<'de> for Ciphertext {
    /// Deserializes a ciphertext from a byte vector.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CiphertextVisitor;

        impl<'de> serde::de::Visitor<'de> for CiphertextVisitor {
            type Value = Ciphertext;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a byte array representing a serialized Ciphertext")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let mut bytes_vec = CxxVector::<u8>::new();
                for &byte in v {
                    bytes_vec.pin_mut().push(byte);
                }
                let mut ct = ffi::DCRTPolyGenNullCiphertext();
                ffi::DCRTPolyDeserializeCiphertextFromBytes(&bytes_vec, ct.pin_mut());
                Ok(Ciphertext(ct))
            }
        }

        deserializer.deserialize_bytes(CiphertextVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi;
    use crate::keys::{KeyPair, PublicKey};
    use cxx::CxxVector;
    use std::sync::Mutex;

    /// Helper function to create a crypto context and key pair for testing
    fn create_test_crypto_context_and_keypair(
    ) -> (cxx::UniquePtr<ffi::CryptoContextDCRTPoly>, KeyPair) {
        let mut cc_params_bfvrns = ffi::GenParamsBFVRNS();
        cc_params_bfvrns.pin_mut().SetPlaintextModulus(65537);
        cc_params_bfvrns.pin_mut().SetMultiplicativeDepth(2);

        let cc = ffi::DCRTPolyGenCryptoContextByParamsBFVRNS(&cc_params_bfvrns);
        cc.EnableByFeature(ffi::PKESchemeFeature::PKE);
        cc.EnableByFeature(ffi::PKESchemeFeature::KEYSWITCH);
        cc.EnableByFeature(ffi::PKESchemeFeature::LEVELEDSHE);

        let key_pair_raw = cc.KeyGen();
        let key_pair = KeyPair(key_pair_raw);

        (cc, key_pair)
    }

    /// Helper function to create a test ciphertext by encrypting some data
    fn create_test_ciphertext(
        cc: &cxx::UniquePtr<ffi::CryptoContextDCRTPoly>,
        public_key: &PublicKey,
        value: i64,
    ) -> Ciphertext {
        let mut values_vec = CxxVector::<i64>::new();
        values_vec.pin_mut().push(value);
        let plaintext = cc.MakePackedPlaintext(&values_vec, 1, 0);
        let ciphertext_raw = cc.EncryptByPublicKey(&public_key.0, &plaintext);
        Ciphertext(ciphertext_raw)
    }

    /// Helper function to create a test ciphertext with vector data
    fn create_test_ciphertext_vector(
        cc: &cxx::UniquePtr<ffi::CryptoContextDCRTPoly>,
        public_key: &PublicKey,
        values: &[i64],
    ) -> Ciphertext {
        let mut values_vec = CxxVector::<i64>::new();
        for &value in values {
            values_vec.pin_mut().push(value);
        }
        let plaintext = cc.MakePackedPlaintext(&values_vec, 1, 0);
        let ciphertext_raw = cc.EncryptByPublicKey(&public_key.0, &plaintext);
        Ciphertext(ciphertext_raw)
    }

    #[test]
    fn test_ciphertext_creation() {
        let (cc, key_pair) = create_test_crypto_context_and_keypair();
        let public_key = key_pair.public_key();

        let ciphertext = create_test_ciphertext(&cc, &public_key, 42);

        // Test that ciphertext is created successfully
        assert!(ciphertext.0.as_ref().is_some());
    }

    #[test]
    fn test_ciphertext_clone() {
        let (cc, key_pair) = create_test_crypto_context_and_keypair();
        let public_key = key_pair.public_key();

        let ciphertext1 = create_test_ciphertext(&cc, &public_key, 42);
        let ciphertext2 = ciphertext1.clone();

        // Test that cloning creates a valid instance
        assert!(ciphertext1.0.as_ref().is_some());
        assert!(ciphertext2.0.as_ref().is_some());

        // Test that both ciphertexts serialize to the same bytes (they represent the same data)
        let mut bytes1 = CxxVector::<u8>::new();
        let mut bytes2 = CxxVector::<u8>::new();
        ffi::DCRTPolySerializeCiphertextToBytes(ciphertext1.0.as_ref().unwrap(), bytes1.pin_mut());
        ffi::DCRTPolySerializeCiphertextToBytes(ciphertext2.0.as_ref().unwrap(), bytes2.pin_mut());

        assert_eq!(bytes1.len(), bytes2.len());
        for (i, (&b1, &b2)) in bytes1.iter().zip(bytes2.iter()).enumerate() {
            assert_eq!(b1, b2, "Byte mismatch at position {}", i);
        }
    }

    #[test]
    fn test_ciphertext_equality() {
        let (cc, key_pair) = create_test_crypto_context_and_keypair();
        let public_key = key_pair.public_key();

        let ciphertext1 = create_test_ciphertext(&cc, &public_key, 42);
        let ciphertext2 = ciphertext1.clone();

        // Test equality between a ciphertext and its clone
        assert_eq!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_ciphertext_inequality() {
        let (cc, key_pair) = create_test_crypto_context_and_keypair();
        let public_key = key_pair.public_key();

        let ciphertext1 = create_test_ciphertext(&cc, &public_key, 42);
        let ciphertext2 = create_test_ciphertext(&cc, &public_key, 100);

        // Test that ciphertexts with different underlying data are different
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_ciphertext_inequality_different_contexts() {
        let (cc1, key_pair1) = create_test_crypto_context_and_keypair();
        let (cc2, key_pair2) = create_test_crypto_context_and_keypair();

        let public_key1 = key_pair1.public_key();
        let public_key2 = key_pair2.public_key();

        let ciphertext1 = create_test_ciphertext(&cc1, &public_key1, 42);
        let ciphertext2 = create_test_ciphertext(&cc2, &public_key2, 42);

        // Test that ciphertexts from different contexts are different even with same value
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_ciphertext_debug() {
        let (cc, key_pair) = create_test_crypto_context_and_keypair();
        let public_key = key_pair.public_key();

        let ciphertext = create_test_ciphertext(&cc, &public_key, 42);
        let debug_string = format!("{:?}", ciphertext);

        // Test that debug formatting works and contains expected elements
        assert!(debug_string.contains("Ciphertext"));
        assert!(debug_string.contains("len_bytes"));

        // The debug representation should contain a non-zero byte length
        let len_bytes = if let Some(start) = debug_string.find("len_bytes: ") {
            let start = start + "len_bytes: ".len();
            if let Some(end) = debug_string[start..].find(' ') {
                debug_string[start..start + end]
                    .parse::<usize>()
                    .unwrap_or(0)
            } else if let Some(end) = debug_string[start..].find('}') {
                debug_string[start..start + end]
                    .parse::<usize>()
                    .unwrap_or(0)
            } else {
                0
            }
        } else {
            0
        };
        assert!(
            len_bytes > 0,
            "Ciphertext should have non-zero serialized size"
        );
    }

    #[test]
    fn test_ciphertext_serialization() {
        let (cc, key_pair) = create_test_crypto_context_and_keypair();
        let public_key = key_pair.public_key();

        let ciphertext = create_test_ciphertext(&cc, &public_key, 42);

        // Test serialization using bincode (binary format)
        let serialized = bincode::serialize(&ciphertext).expect("Serialization should succeed");
        assert!(!serialized.is_empty());
    }

    #[test]
    fn test_ciphertext_deserialization() {
        let (cc, key_pair) = create_test_crypto_context_and_keypair();
        let public_key = key_pair.public_key();

        let original_ciphertext = create_test_ciphertext(&cc, &public_key, 42);

        // Test serialization/deserialization using bincode
        let serialized =
            bincode::serialize(&original_ciphertext).expect("Serialization should succeed");
        let deserialized_ciphertext: Ciphertext =
            bincode::deserialize(&serialized).expect("Deserialization should succeed");

        // Test that the deserialized ciphertext equals the original
        assert_eq!(original_ciphertext, deserialized_ciphertext);
    }

    #[test]
    fn test_ciphertext_serialization_roundtrip() {
        let (cc, key_pair) = create_test_crypto_context_and_keypair();
        let public_key = key_pair.public_key();

        let original_ciphertext = create_test_ciphertext(&cc, &public_key, 42);

        // Test bincode roundtrip
        let binary_serialized =
            bincode::serialize(&original_ciphertext).expect("Binary serialization should succeed");
        let binary_deserialized: Ciphertext = bincode::deserialize(&binary_serialized)
            .expect("Binary deserialization should succeed");
        assert_eq!(original_ciphertext, binary_deserialized);
    }

    #[test]
    fn test_ciphertext_serialization_with_different_values() {
        let (cc, key_pair) = create_test_crypto_context_and_keypair();
        let public_key = key_pair.public_key();

        let ciphertext1 = create_test_ciphertext(&cc, &public_key, 42);
        let ciphertext2 = create_test_ciphertext(&cc, &public_key, 100);

        assert_ne!(ciphertext1, ciphertext2);

        // Serialize both ciphertexts using bincode
        let serialized1 = bincode::serialize(&ciphertext1).expect("Serialization should succeed");
        let serialized2 = bincode::serialize(&ciphertext2).expect("Serialization should succeed");

        // Different ciphertexts should have different serializations
        assert_ne!(serialized1, serialized2);

        // Deserialize and verify they're still different
        let deserialized1: Ciphertext =
            bincode::deserialize(&serialized1).expect("Deserialization should succeed");
        let deserialized2: Ciphertext =
            bincode::deserialize(&serialized2).expect("Deserialization should succeed");

        assert_ne!(deserialized1, deserialized2);
        assert_eq!(ciphertext1, deserialized1);
        assert_eq!(ciphertext2, deserialized2);
    }

    #[test]
    fn test_ciphertext_hash_consistency() {
        let (cc, key_pair) = create_test_crypto_context_and_keypair();
        let public_key = key_pair.public_key();

        let ciphertext = create_test_ciphertext(&cc, &public_key, 42);
        let cloned_ciphertext = ciphertext.clone();

        // Calculate consistency by comparing serialized bytes
        let mut out_bytes1 = CxxVector::<u8>::new();
        ffi::DCRTPolySerializeCiphertextToBytes(
            ciphertext.0.as_ref().unwrap(),
            out_bytes1.pin_mut(),
        );

        let mut out_bytes2 = CxxVector::<u8>::new();
        ffi::DCRTPolySerializeCiphertextToBytes(
            cloned_ciphertext.0.as_ref().unwrap(),
            out_bytes2.pin_mut(),
        );

        // Test that equal ciphertexts have the same serialized representation
        assert_eq!(out_bytes1.len(), out_bytes2.len());
        for (i, (&byte1, &byte2)) in out_bytes1.iter().zip(out_bytes2.iter()).enumerate() {
            assert_eq!(byte1, byte2, "Byte mismatch at position {}", i);
        }
    }

    #[test]
    fn test_ciphertext_with_vector_data() {
        let (cc, key_pair) = create_test_crypto_context_and_keypair();
        let public_key = key_pair.public_key();

        let values = vec![1, 2, 3, 4, 5];
        let ciphertext = create_test_ciphertext_vector(&cc, &public_key, &values);

        // Test that vector ciphertext works
        assert!(ciphertext.0.as_ref().is_some());

        // Test cloning and equality
        let cloned_ciphertext = ciphertext.clone();
        assert_eq!(ciphertext, cloned_ciphertext);

        // Test serialization
        let serialized = bincode::serialize(&ciphertext).expect("Serialization should succeed");
        let deserialized: Ciphertext =
            bincode::deserialize(&serialized).expect("Deserialization should succeed");
        assert_eq!(ciphertext, deserialized);
    }

    #[test]
    fn test_ciphertext_multiple_operations() {
        let (cc, key_pair) = create_test_crypto_context_and_keypair();
        let public_key = key_pair.public_key();

        // Create multiple ciphertexts and perform various operations
        let ciphertexts: Vec<Ciphertext> = (0..10)
            .map(|i| create_test_ciphertext(&cc, &public_key, i))
            .collect();

        // Test that all ciphertexts are valid
        for ct in &ciphertexts {
            assert!(ct.0.as_ref().is_some());
        }

        // Test that they're all different
        for i in 0..ciphertexts.len() {
            for j in i + 1..ciphertexts.len() {
                assert_ne!(ciphertexts[i], ciphertexts[j]);
            }
        }

        // Test cloning all
        let cloned_ciphertexts: Vec<Ciphertext> = ciphertexts.iter().map(|ct| ct.clone()).collect();
        for (original, cloned) in ciphertexts.iter().zip(cloned_ciphertexts.iter()) {
            assert_eq!(original, cloned);
        }

        // Test serialization of all
        let serialized_ciphertexts: Vec<Vec<u8>> = ciphertexts
            .iter()
            .map(|ct| bincode::serialize(ct).expect("Serialization should succeed"))
            .collect();

        let deserialized_ciphertexts: Vec<Ciphertext> = serialized_ciphertexts
            .iter()
            .map(|bytes| bincode::deserialize(bytes).expect("Deserialization should succeed"))
            .collect();

        for (original, deserialized) in ciphertexts.iter().zip(deserialized_ciphertexts.iter()) {
            assert_eq!(original, deserialized);
        }
    }

    #[test]
    fn test_concurrent_ciphertext_operations() {
        use std::sync::{Arc, Barrier};
        use std::thread;
        use std::time::Duration;

        const NUM_THREADS: usize = 8;
        const ITERATIONS_PER_THREAD: usize = 50;

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
                        // Create crypto context and key pair
                        let (cc, key_pair) = create_test_crypto_context_and_keypair();
                        let public_key = key_pair.public_key();

                        // Create multiple ciphertexts
                        let ciphertext1 =
                            create_test_ciphertext(&cc, &public_key, thread_id as i64);
                        let ciphertext2 =
                            create_test_ciphertext(&cc, &public_key, iteration as i64);
                        let vector_values = vec![thread_id as i64, iteration as i64, 42];
                        let ciphertext3 =
                            create_test_ciphertext_vector(&cc, &public_key, &vector_values);

                        // Clone operations
                        let ciphertext1_clone = ciphertext1.clone();
                        let ciphertext2_clone = ciphertext2.clone();
                        let ciphertext3_clone = ciphertext3.clone();

                        // Equality checks
                        assert_eq!(ciphertext1, ciphertext1_clone);
                        assert_eq!(ciphertext2, ciphertext2_clone);
                        assert_eq!(ciphertext3, ciphertext3_clone);

                        // Inequality checks
                        assert_ne!(ciphertext1, ciphertext2);
                        assert_ne!(ciphertext1, ciphertext3);
                        assert_ne!(ciphertext2, ciphertext3);

                        // Serialization operations
                        let ct1_serialized = bincode::serialize(&ciphertext1)
                            .expect("Ciphertext1 serialization should succeed");
                        let ct2_serialized = bincode::serialize(&ciphertext2)
                            .expect("Ciphertext2 serialization should succeed");
                        let ct3_serialized = bincode::serialize(&ciphertext3)
                            .expect("Ciphertext3 serialization should succeed");

                        // Deserialization operations
                        let _ct1_deserialized: Ciphertext = bincode::deserialize(&ct1_serialized)
                            .expect("Ciphertext1 deserialization should succeed");
                        let _ct2_deserialized: Ciphertext = bincode::deserialize(&ct2_serialized)
                            .expect("Ciphertext2 deserialization should succeed");
                        let _ct3_deserialized: Ciphertext = bincode::deserialize(&ct3_serialized)
                            .expect("Ciphertext3 deserialization should succeed");

                        // Debug formatting
                        let _ct1_debug = format!("{:?}", ciphertext1);
                        let _ct2_debug = format!("{:?}", ciphertext2);
                        let _ct3_debug = format!("{:?}", ciphertext3);

                        // FFI serialization operations
                        let mut out_bytes1 = CxxVector::<u8>::new();
                        ffi::DCRTPolySerializeCiphertextToBytes(
                            ciphertext1.0.as_ref().unwrap(),
                            out_bytes1.pin_mut(),
                        );

                        let mut out_bytes2 = CxxVector::<u8>::new();
                        ffi::DCRTPolySerializeCiphertextToBytes(
                            ciphertext2.0.as_ref().unwrap(),
                            out_bytes2.pin_mut(),
                        );

                        let mut out_bytes3 = CxxVector::<u8>::new();
                        ffi::DCRTPolySerializeCiphertextToBytes(
                            ciphertext3.0.as_ref().unwrap(),
                            out_bytes3.pin_mut(),
                        );

                        // Create another crypto context to test cross-context inequality
                        let (cc2, key_pair2) = create_test_crypto_context_and_keypair();
                        let public_key2 = key_pair2.public_key();
                        let ciphertext4 =
                            create_test_ciphertext(&cc2, &public_key2, thread_id as i64);

                        // Test inequality across contexts (this often triggers segfault issues)
                        assert_ne!(ciphertext1, ciphertext4);

                        // Test equality comparisons via FFI
                        assert!(ffi::AreCiphertextsEqual(
                            &ciphertext1.0,
                            &ciphertext1_clone.0
                        ));
                        assert!(ffi::AreCiphertextsEqual(
                            &ciphertext2.0,
                            &ciphertext2_clone.0
                        ));
                        assert!(ffi::AreCiphertextsEqual(
                            &ciphertext3.0,
                            &ciphertext3_clone.0
                        ));
                        assert!(!ffi::AreCiphertextsEqual(&ciphertext1.0, &ciphertext2.0));
                        assert!(!ffi::AreCiphertextsEqual(&ciphertext1.0, &ciphertext4.0));
                    });

                    if result.is_err() {
                        let mut counter = panic_counter_clone.lock().unwrap();
                        *counter += 1;
                        eprintln!(
                            "Thread {} panic at iteration {}: {:?}",
                            thread_id, iteration, result
                        );
                        break; // Exit this thread's loop on panic
                    }

                    // Small delay between iterations
                    if iteration % 10 == 0 {
                        thread::sleep(Duration::from_millis(1));
                    }
                }

                println!("Ciphertext Thread {} completed successfully", thread_id);
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for (i, handle) in handles.into_iter().enumerate() {
            match handle.join() {
                Ok(_) => println!("Ciphertext Thread {} joined successfully", i),
                Err(e) => {
                    eprintln!("Ciphertext Thread {} panicked: {:?}", i, e);
                    let mut counter = panic_counter.lock().unwrap();
                    *counter += 1;
                }
            }
        }

        let final_panic_count = *panic_counter.lock().unwrap();

        if final_panic_count > 0 {
            panic!(
                "Concurrent ciphertext test detected {} panics/segfaults. This indicates thread safety issues!",
                final_panic_count
            );
        }

        println!(
            "Concurrent ciphertext test completed successfully - no thread safety issues detected"
        );
    }

    #[test]
    fn test_stress_ciphertext_creation() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        const NUM_THREADS: usize = 4;
        const CIPHERTEXTS_PER_THREAD: usize = 20;

        let barrier = Arc::new(Barrier::new(NUM_THREADS));
        let mut handles = Vec::new();

        for thread_id in 0..NUM_THREADS {
            let barrier_clone = Arc::clone(&barrier);

            let handle = thread::spawn(move || {
                barrier_clone.wait();

                let mut contexts_and_ciphertexts = Vec::new();

                // Create multiple contexts and ciphertexts rapidly
                for i in 0..CIPHERTEXTS_PER_THREAD {
                    let result = std::panic::catch_unwind(|| {
                        let (cc, key_pair) = create_test_crypto_context_and_keypair();
                        let public_key = key_pair.public_key();

                        // Create multiple ciphertexts per context
                        let ct1 = create_test_ciphertext(&cc, &public_key, i as i64);
                        let ct2 = create_test_ciphertext(&cc, &public_key, (i * 2) as i64);
                        let vector_values = vec![i as i64, thread_id as i64];
                        let ct3 = create_test_ciphertext_vector(&cc, &public_key, &vector_values);

                        (cc, key_pair, vec![ct1, ct2, ct3])
                    });

                    match result {
                        Ok((cc, key_pair, ciphertexts)) => {
                            // Store them to prevent immediate destruction
                            contexts_and_ciphertexts.push((cc, key_pair, ciphertexts));

                            // Perform some operations on the latest ciphertexts
                            if let Some((_, _, last_ciphertexts)) = contexts_and_ciphertexts.last()
                            {
                                for ct in last_ciphertexts {
                                    let _cloned = ct.clone();
                                    let _debug = format!("{:?}", ct);
                                }
                            }
                        }
                        Err(e) => {
                            panic!(
                                "Thread {} panicked at ciphertext creation {}: {:?}",
                                thread_id, i, e
                            );
                        }
                    }
                }

                println!(
                    "Thread {} created {} contexts with ciphertexts successfully",
                    thread_id, CIPHERTEXTS_PER_THREAD
                );

                // Test operations on all created ciphertexts
                for (i, (_, _, ciphertexts)) in contexts_and_ciphertexts.iter().enumerate() {
                    for (j, ciphertext) in ciphertexts.iter().enumerate() {
                        let result = std::panic::catch_unwind(|| {
                            // Serialize/deserialize
                            let ct_bytes = bincode::serialize(ciphertext).unwrap();
                            let _: Ciphertext = bincode::deserialize(&ct_bytes).unwrap();

                            // Clone and compare
                            let cloned = ciphertext.clone();
                            assert_eq!(ciphertext, &cloned);

                            // FFI operations
                            let mut out_bytes = CxxVector::<u8>::new();
                            ffi::DCRTPolySerializeCiphertextToBytes(
                                ciphertext.0.as_ref().unwrap(),
                                out_bytes.pin_mut(),
                            );
                            assert!(out_bytes.len() > 0);
                        });

                        if result.is_err() {
                            panic!(
                                "Thread {} panicked during operations on context {} ciphertext {}: {:?}",
                                thread_id, i, j, result
                            );
                        }
                    }
                }
            });

            handles.push(handle);
        }

        for (i, handle) in handles.into_iter().enumerate() {
            match handle.join() {
                Ok(_) => println!("Ciphertext stress test thread {} completed successfully", i),
                Err(e) => panic!("Ciphertext stress test thread {} panicked: {:?}", i, e),
            }
        }

        println!("Ciphertext stress test completed successfully");
    }

    #[test]
    fn test_massive_concurrent_ciphertext_load() {
        use std::sync::{Arc, Barrier};
        use std::thread;
        use std::time::Duration;

        const NUM_THREADS: usize = 16;
        const ITERATIONS_PER_THREAD: usize = 25;

        let barrier = Arc::new(Barrier::new(NUM_THREADS));
        let mut handles = Vec::new();
        let panic_counter = Arc::new(Mutex::new(0));

        for thread_id in 0..NUM_THREADS {
            let barrier_clone = Arc::clone(&barrier);
            let panic_counter_clone = Arc::clone(&panic_counter);

            let handle = thread::spawn(move || {
                barrier_clone.wait();

                // Staggered start to create more race conditions
                thread::sleep(Duration::from_millis((thread_id % 4) as u64));

                for iteration in 0..ITERATIONS_PER_THREAD {
                    let result = std::panic::catch_unwind(|| {
                        // Create multiple crypto contexts simultaneously
                        let (cc1, key_pair1) = create_test_crypto_context_and_keypair();
                        let (cc2, key_pair2) = create_test_crypto_context_and_keypair();

                        let public_key1 = key_pair1.public_key();
                        let public_key2 = key_pair2.public_key();

                        // Create many ciphertexts rapidly
                        let mut ciphertexts = Vec::new();
                        for i in 0..5 {
                            let value = (thread_id * 1000 + iteration * 10 + i) as i64;
                            ciphertexts.push(create_test_ciphertext(&cc1, &public_key1, value));
                            ciphertexts.push(create_test_ciphertext(&cc2, &public_key2, value));

                            let vector_vals = vec![value, value + 1, value + 2];
                            ciphertexts.push(create_test_ciphertext_vector(
                                &cc1,
                                &public_key1,
                                &vector_vals,
                            ));
                        }

                        // Perform massive operations on all ciphertexts
                        for (i, ct) in ciphertexts.iter().enumerate() {
                            // Clone operations
                            let cloned = ct.clone();
                            assert_eq!(ct, &cloned);

                            // Serialization
                            let serialized = bincode::serialize(ct).unwrap();
                            let deserialized: Ciphertext =
                                bincode::deserialize(&serialized).unwrap();
                            assert_eq!(ct, &deserialized);

                            // FFI operations
                            let mut out_bytes = CxxVector::<u8>::new();
                            ffi::DCRTPolySerializeCiphertextToBytes(
                                ct.0.as_ref().unwrap(),
                                out_bytes.pin_mut(),
                            );

                            // Cross-comparisons (high chance of triggering thread safety issues)
                            for (j, other_ct) in ciphertexts.iter().enumerate() {
                                if i != j {
                                    let _are_equal = ffi::AreCiphertextsEqual(&ct.0, &other_ct.0);
                                    // Most should be different unless they have the same value
                                    // (which is possible but unlikely with our value generation)
                                }
                            }

                            // Debug formatting
                            let _debug = format!("{:?}", ct);
                        }

                        // Cross-context comparisons (most likely to trigger segfaults)
                        for i in 0..ciphertexts.len() {
                            for j in (i + 1)..ciphertexts.len() {
                                let _are_equal = ciphertexts[i] == ciphertexts[j];
                                let _are_equal_ffi =
                                    ffi::AreCiphertextsEqual(&ciphertexts[i].0, &ciphertexts[j].0);
                            }
                        }
                    });

                    if result.is_err() {
                        let mut counter = panic_counter_clone.lock().unwrap();
                        *counter += 1;
                        eprintln!(
                            "Massive load Thread {} panic at iteration {}: {:?}",
                            thread_id, iteration, result
                        );
                        break;
                    }

                    // Very short sleep to allow other threads to interleave
                    if iteration % 5 == 0 {
                        thread::sleep(Duration::from_millis(1));
                    }
                }

                println!("Massive load Thread {} completed successfully", thread_id);
            });

            handles.push(handle);
        }

        for (i, handle) in handles.into_iter().enumerate() {
            match handle.join() {
                Ok(_) => println!("Massive load Thread {} joined successfully", i),
                Err(e) => {
                    eprintln!("Massive load Thread {} panicked: {:?}", i, e);
                    let mut counter = panic_counter.lock().unwrap();
                    *counter += 1;
                }
            }
        }

        let final_panic_count = *panic_counter.lock().unwrap();

        if final_panic_count > 0 {
            panic!(
                "Massive concurrent ciphertext load test detected {} panics/segfaults. This indicates serious thread safety issues!",
                final_panic_count
            );
        }

        println!("Massive concurrent ciphertext load test completed successfully - no thread safety issues detected");
    }
}
