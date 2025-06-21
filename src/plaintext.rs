use crate::ffi;
use cxx::{CxxVector, UniquePtr};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A wrapper for a plaintext object.
pub struct Plaintext(pub(crate) UniquePtr<ffi::Plaintext>);
impl Clone for Plaintext {
    /// Clones the plaintext through serialization as there is no clone function in the C++ API.
    fn clone(&self) -> Self {
        // clone through serialization
        let mut out_bytes = CxxVector::<u8>::new();
        ffi::DCRTPolySerializePlaintextToBytes(self.0.as_ref().unwrap(), out_bytes.pin_mut());
        let mut new_plaintext = ffi::GenNullPlainText();
        ffi::DCRTPolyDeserializePlaintextFromBytes(&out_bytes, new_plaintext.pin_mut());
        Plaintext(new_plaintext)
    }
}

impl std::fmt::Debug for Plaintext {
    /// Formats the ciphertext by showing its serialized size, avoiding printing large objects.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out_bytes = CxxVector::<u8>::new();
        ffi::DCRTPolySerializePlaintextToBytes(self.0.as_ref().unwrap(), out_bytes.pin_mut());
        f.debug_struct("Plaintext")
            .field("len_bytes", &out_bytes.len())
            .finish()
    }
}

impl PartialEq for Plaintext {
    /// Checks for equality by calling the underlying C++ comparison function.
    fn eq(&self, other: &Self) -> bool {
        ffi::ArePlaintextsEqual(&self.0, &other.0)
    }
}
impl Eq for Plaintext {}

impl Serialize for Plaintext {
    /// Serializes the ciphertext into a byte vector.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut out_bytes = CxxVector::<u8>::new();
        ffi::DCRTPolySerializePlaintextToBytes(self.0.as_ref().unwrap(), out_bytes.pin_mut());
        serializer.serialize_bytes(out_bytes.as_slice())
    }
}

impl<'de> Deserialize<'de> for Plaintext {
    /// Deserializes a ciphertext from a byte vector.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PlaintextVisitor;

        impl<'de> serde::de::Visitor<'de> for PlaintextVisitor {
            type Value = Plaintext;

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
                let mut pt = ffi::GenNullPlainText();
                ffi::DCRTPolyDeserializePlaintextFromBytes(&bytes_vec, pt.pin_mut());
                Ok(Plaintext(pt))
            }
        }

        deserializer.deserialize_bytes(PlaintextVisitor)
    }
}

impl Plaintext {
    /// Retrieves the packed integer values from the plaintext.
    pub fn get_packed_value(&self) -> Vec<i64> {
        self.0.GetPackedValue().as_slice().to_vec()
    }

    /// Returns a string representation of the plaintext data.
    pub fn get_string(&self) -> String {
        self.0.GetString()
    }

    /// Decodes the packed values as UTF-8 string bytes.
    /// This is useful when the plaintext was created from string bytes.
    pub fn get_string_from_bytes(&self) -> Result<String, std::string::FromUtf8Error> {
        let packed_values = self.get_packed_value();
        let bytes: Vec<u8> = packed_values.iter().map(|&val| val as u8).collect();
        String::from_utf8(bytes)
    }

    /// Gets the length of the plaintext data.
    pub fn len(&self) -> usize {
        self.0.GetLength()
    }

    /// Checks if the plaintext is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Sets the length of the plaintext vector.
    /// This is necessary before accessing vector data if the length is not implicitly known.
    pub fn set_length(&mut self, len: usize) {
        self.0.pin_mut().SetLength(len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi;
    use crate::keys::KeyPair;
    use cxx::CxxVector;
    use std::sync::Mutex;

    /// Helper function to create a crypto context and key pair for testing
    fn create_test_crypto_context_and_keypair(
    ) -> (cxx::UniquePtr<ffi::CryptoContextDCRTPoly>, KeyPair) {
        let mut cc_params_bfvrns = ffi::GenParamsBFVRNS();
        cc_params_bfvrns.pin_mut().SetPlaintextModulus(65537);
        cc_params_bfvrns.pin_mut().SetMultiplicativeDepth(1);

        let cc = ffi::DCRTPolyGenCryptoContextByParamsBFVRNS(&cc_params_bfvrns);
        cc.EnableByFeature(ffi::PKESchemeFeature::PKE);
        cc.EnableByFeature(ffi::PKESchemeFeature::KEYSWITCH);
        cc.EnableByFeature(ffi::PKESchemeFeature::LEVELEDSHE);

        let key_pair_raw = cc.KeyGen();
        let key_pair = KeyPair(key_pair_raw);

        (cc, key_pair)
    }

    /// Helper function to create a test plaintext with a single value
    fn create_test_plaintext_single(
        cc: &cxx::UniquePtr<ffi::CryptoContextDCRTPoly>,
        value: i64,
    ) -> Plaintext {
        let mut values_vec = CxxVector::<i64>::new();
        values_vec.pin_mut().push(value);
        let plaintext_raw = cc.MakePackedPlaintext(&values_vec, 1, 0);
        Plaintext(plaintext_raw)
    }

    /// Helper function to create a test plaintext with vector data
    fn create_test_plaintext_vector(
        cc: &cxx::UniquePtr<ffi::CryptoContextDCRTPoly>,
        values: &[i64],
    ) -> Plaintext {
        let mut values_vec = CxxVector::<i64>::new();
        for &value in values {
            values_vec.pin_mut().push(value);
        }
        let plaintext_raw = cc.MakePackedPlaintext(&values_vec, 1, 0);
        Plaintext(plaintext_raw)
    }

    /// Helper function to create a string plaintext
    fn create_test_plaintext_string(
        cc: &cxx::UniquePtr<ffi::CryptoContextDCRTPoly>,
        text: &str,
    ) -> Plaintext {
        // Convert string to bytes and then to i64 values
        let bytes = text.as_bytes();
        let mut values_vec = CxxVector::<i64>::new();
        for &byte in bytes {
            values_vec.pin_mut().push(byte as i64);
        }
        let plaintext_raw = cc.MakePackedPlaintext(&values_vec, 1, 0);
        Plaintext(plaintext_raw)
    }

    #[test]
    fn test_plaintext_creation_single_value() {
        let (cc, _key_pair) = create_test_crypto_context_and_keypair();

        let plaintext = create_test_plaintext_single(&cc, 42);

        // Test that plaintext is created successfully
        assert!(plaintext.0.as_ref().is_some());
        assert!(!plaintext.is_empty());
        assert!(plaintext.len() > 0);
    }

    #[test]
    fn test_plaintext_creation_vector() {
        let (cc, _key_pair) = create_test_crypto_context_and_keypair();

        let values = vec![1, 2, 3, 4, 5];
        let plaintext = create_test_plaintext_vector(&cc, &values);

        // Test that plaintext is created successfully
        assert!(plaintext.0.as_ref().is_some());
        assert!(!plaintext.is_empty());
        assert!(plaintext.len() > 0);
    }

    #[test]
    fn test_plaintext_creation_string() {
        let (cc, _key_pair) = create_test_crypto_context_and_keypair();

        let plaintext = create_test_plaintext_string(&cc, "Hello, World!");

        // Test that string plaintext is created successfully
        assert!(plaintext.0.as_ref().is_some());
        assert!(!plaintext.is_empty());
        assert!(plaintext.len() > 0);
    }

    #[test]
    fn test_plaintext_get_packed_value() {
        let (cc, _key_pair) = create_test_crypto_context_and_keypair();

        let original_values = vec![1, 2, 3, 4, 5];
        let plaintext = create_test_plaintext_vector(&cc, &original_values);

        let retrieved_values = plaintext.get_packed_value();

        // Test that we can retrieve the packed values
        assert!(!retrieved_values.is_empty());

        // The first few values should match what we put in
        for (i, &original_val) in original_values.iter().enumerate() {
            if i < retrieved_values.len() {
                assert_eq!(retrieved_values[i], original_val);
            }
        }
    }

    #[test]
    fn test_plaintext_get_string() {
        let (cc, _key_pair) = create_test_crypto_context_and_keypair();

        let plaintext = create_test_plaintext_single(&cc, 42);
        let string_repr = plaintext.get_string();

        // Test that string representation is not empty
        assert!(!string_repr.is_empty());
        assert!(string_repr.len() > 0);
    }

    #[test]
    fn test_plaintext_string_content() {
        let (cc, _key_pair) = create_test_crypto_context_and_keypair();

        let test_string = "Hello, World!";
        let plaintext = create_test_plaintext_string(&cc, test_string);

        // Test that we can recover the original string from bytes
        let recovered_string = plaintext
            .get_string_from_bytes()
            .expect("Failed to decode string from bytes");
        assert_eq!(
            recovered_string, test_string,
            "Recovered string {:?} does not match original string {:?}",
            recovered_string, test_string
        );

        // Test that the packed values match the expected byte values
        let packed_values = plaintext.get_packed_value();
        let expected_bytes: Vec<i64> = test_string.as_bytes().iter().map(|&b| b as i64).collect();
        assert_eq!(
            packed_values[..expected_bytes.len()],
            expected_bytes,
            "Packed values {:?} do not match expected bytes {:?}",
            &packed_values[..expected_bytes.len()],
            expected_bytes
        );
    }

    #[test]
    fn test_plaintext_length_operations() {
        let (cc, _key_pair) = create_test_crypto_context_and_keypair();

        let mut plaintext = create_test_plaintext_single(&cc, 42);
        let original_len = plaintext.len();

        // Test that length is positive
        assert!(original_len > 0);
        assert!(!plaintext.is_empty());

        // Test setting length
        let new_len = original_len + 10;
        plaintext.set_length(new_len);
        assert_eq!(plaintext.len(), new_len);
    }

    #[test]
    fn test_plaintext_debug_formatting() {
        let (cc, _key_pair) = create_test_crypto_context_and_keypair();

        let plaintext = create_test_plaintext_single(&cc, 42);
        let debug_string = format!("{:?}", plaintext);

        // Test that debug formatting works and contains expected elements
        assert!(debug_string.contains("Plaintext"));
        assert!(debug_string.contains("len"));
        assert!(!debug_string.is_empty());
    }

    #[test]
    fn test_plaintext_empty_check() {
        let (cc, _key_pair) = create_test_crypto_context_and_keypair();

        // Create a plaintext with data
        let plaintext_with_data = create_test_plaintext_single(&cc, 42);
        assert!(!plaintext_with_data.is_empty());
        assert!(plaintext_with_data.len() > 0);

        // Test that is_empty is consistent with len() == 0
        assert_eq!(
            plaintext_with_data.is_empty(),
            plaintext_with_data.len() == 0
        );
    }

    #[test]
    fn test_plaintext_multiple_values() {
        let (cc, _key_pair) = create_test_crypto_context_and_keypair();

        let values = vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        let plaintext = create_test_plaintext_vector(&cc, &values);

        let retrieved_values = plaintext.get_packed_value();
        assert!(!retrieved_values.is_empty());

        // Check that the first few values match
        for (i, &original_val) in values.iter().enumerate() {
            if i < retrieved_values.len() {
                assert_eq!(retrieved_values[i], original_val);
            }
        }
    }

    #[test]
    fn test_plaintext_large_values() {
        let (cc, _key_pair) = create_test_crypto_context_and_keypair();

        // Use values that are large but within the plaintext modulus (65537)
        let large_values = vec![65536, 32768, 16384, 8192];
        let plaintext = create_test_plaintext_vector(&cc, &large_values);

        let retrieved_values = plaintext.get_packed_value();
        assert!(!retrieved_values.is_empty());

        // Check that the first few values match what we put in
        for (i, &original_val) in large_values.iter().enumerate() {
            if i < retrieved_values.len() {
                assert_eq!(retrieved_values[i], original_val);
            }
        }
    }

    #[test]
    fn test_plaintext_negative_values() {
        let (cc, _key_pair) = create_test_crypto_context_and_keypair();

        let negative_values = vec![-1, -10, -100, -1000];
        let plaintext = create_test_plaintext_vector(&cc, &negative_values);

        let retrieved_values = plaintext.get_packed_value();
        assert!(!retrieved_values.is_empty());

        // Negative values might be represented differently due to modular arithmetic
        // but the structure should be preserved
        assert!(retrieved_values.len() >= negative_values.len());
    }

    #[test]
    fn test_plaintext_zero_values() {
        let (cc, _key_pair) = create_test_crypto_context_and_keypair();

        let zero_values = vec![0, 0, 0, 0, 0];
        let plaintext = create_test_plaintext_vector(&cc, &zero_values);

        let retrieved_values = plaintext.get_packed_value();
        assert!(!retrieved_values.is_empty());

        // Zero values should be preserved
        for &val in &retrieved_values[..zero_values.len().min(retrieved_values.len())] {
            assert_eq!(val, 0);
        }
    }

    #[test]
    fn test_concurrent_plaintext_operations() {
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
                        // Create crypto context
                        let (cc, _key_pair) = create_test_crypto_context_and_keypair();

                        // Create multiple plaintexts with different data
                        let plaintext1 = create_test_plaintext_single(&cc, thread_id as i64);
                        let plaintext2 = create_test_plaintext_single(&cc, iteration as i64);

                        let vector_values = vec![thread_id as i64, iteration as i64, 42];
                        let plaintext3 = create_test_plaintext_vector(&cc, &vector_values);

                        let string_value = format!("thread_{}_iter_{}", thread_id, iteration);
                        let plaintext4 = create_test_plaintext_string(&cc, &string_value);

                        // Perform various operations on all plaintexts
                        let plaintexts = vec![plaintext1, plaintext2, plaintext3, plaintext4];

                        for (i, plaintext) in plaintexts.iter().enumerate() {
                            // Length operations
                            let len = plaintext.len();

                            let is_empty = plaintext.is_empty();
                            assert_eq!(is_empty, len == 0);

                            // String representation
                            let string_repr = plaintext.get_string();
                            assert!(!string_repr.is_empty());

                            // Debug formatting
                            let debug_repr = format!("{:?}", plaintext);
                            assert!(!debug_repr.is_empty());
                            assert!(debug_repr.contains("Plaintext"));

                            // For packed plaintexts (not string), get packed values
                            if i < 3 {
                                // First 3 are packed plaintexts
                                let packed_values = plaintext.get_packed_value();
                                assert!(!packed_values.is_empty());
                            }
                        }

                        // Test mutable operations on a separate plaintext
                        let mut mutable_plaintext = create_test_plaintext_single(&cc, 999);
                        let original_len = mutable_plaintext.len();

                        // Set different lengths
                        mutable_plaintext.set_length(original_len + 5);
                        assert_eq!(mutable_plaintext.len(), original_len + 5);

                        mutable_plaintext.set_length(original_len);
                        assert_eq!(mutable_plaintext.len(), original_len);
                    });

                    if result.is_err() {
                        let mut counter = panic_counter_clone.lock().unwrap();
                        *counter += 1;
                        eprintln!(
                            "Plaintext Thread {} panic at iteration {}: {:?}",
                            thread_id, iteration, result
                        );
                        break; // Exit this thread's loop on panic
                    }

                    // Small delay between iterations
                    if iteration % 10 == 0 {
                        thread::sleep(Duration::from_millis(1));
                    }
                }

                println!("Plaintext Thread {} completed successfully", thread_id);
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for (i, handle) in handles.into_iter().enumerate() {
            match handle.join() {
                Ok(_) => println!("Plaintext Thread {} joined successfully", i),
                Err(e) => {
                    eprintln!("Plaintext Thread {} panicked: {:?}", i, e);
                    let mut counter = panic_counter.lock().unwrap();
                    *counter += 1;
                }
            }
        }

        let final_panic_count = *panic_counter.lock().unwrap();

        if final_panic_count > 0 {
            panic!(
                "Concurrent plaintext test detected {} panics/segfaults. This indicates thread safety issues!",
                final_panic_count
            );
        }

        println!(
            "Concurrent plaintext test completed successfully - no thread safety issues detected"
        );
    }

    #[test]
    fn test_stress_plaintext_creation() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        const NUM_THREADS: usize = 4;
        const PLAINTEXTS_PER_THREAD: usize = 30;

        let barrier = Arc::new(Barrier::new(NUM_THREADS));
        let mut handles = Vec::new();

        for thread_id in 0..NUM_THREADS {
            let barrier_clone = Arc::clone(&barrier);

            let handle = thread::spawn(move || {
                barrier_clone.wait();

                let mut contexts_and_plaintexts = Vec::new();

                // Create multiple contexts and plaintexts rapidly
                for i in 0..PLAINTEXTS_PER_THREAD {
                    let result = std::panic::catch_unwind(|| {
                        let (cc, _key_pair) = create_test_crypto_context_and_keypair();

                        // Create multiple plaintexts per context
                        let pt1 = create_test_plaintext_single(&cc, i as i64);
                        let pt2 = create_test_plaintext_single(&cc, (i * 2) as i64);

                        let vector_values =
                            vec![i as i64, thread_id as i64, (i + thread_id) as i64];
                        let pt3 = create_test_plaintext_vector(&cc, &vector_values);

                        let string_value = format!("stress_test_{}_{}", thread_id, i);
                        let pt4 = create_test_plaintext_string(&cc, &string_value);

                        (cc, _key_pair, vec![pt1, pt2, pt3, pt4])
                    });

                    match result {
                        Ok((cc, key_pair, plaintexts)) => {
                            // Store them to prevent immediate destruction
                            contexts_and_plaintexts.push((cc, key_pair, plaintexts));

                            // Perform some operations on the latest plaintexts
                            if let Some((_, _, last_plaintexts)) = contexts_and_plaintexts.last() {
                                for pt in last_plaintexts {
                                    let _len = pt.len();
                                    let _is_empty = pt.is_empty();
                                    let _string_repr = pt.get_string();
                                    let _debug = format!("{:?}", pt);
                                }
                            }
                        }
                        Err(e) => {
                            panic!(
                                "Thread {} panicked at plaintext creation {}: {:?}",
                                thread_id, i, e
                            );
                        }
                    }
                }

                println!(
                    "Thread {} created {} contexts with plaintexts successfully",
                    thread_id, PLAINTEXTS_PER_THREAD
                );

                // Test operations on all created plaintexts
                for (i, (_, _, plaintexts)) in contexts_and_plaintexts.iter().enumerate() {
                    for (j, plaintext) in plaintexts.iter().enumerate() {
                        let result = std::panic::catch_unwind(|| {
                            // Various operations
                            let len = plaintext.len();
                            let is_empty = plaintext.is_empty();
                            let string_repr = plaintext.get_string();
                            let debug_repr = format!("{:?}", plaintext);

                            // Consistency checks
                            assert_eq!(is_empty, len == 0);
                            assert!(!string_repr.is_empty());
                            assert!(!debug_repr.is_empty());

                            // For packed plaintexts, get packed values
                            if j < 3 {
                                let _packed_values = plaintext.get_packed_value();
                            }
                        });

                        if result.is_err() {
                            panic!(
                                "Thread {} panicked during operations on context {} plaintext {}: {:?}",
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
                Ok(_) => println!("Plaintext stress test thread {} completed successfully", i),
                Err(e) => panic!("Plaintext stress test thread {} panicked: {:?}", i, e),
            }
        }

        println!("Plaintext stress test completed successfully");
    }

    #[test]
    fn test_massive_concurrent_plaintext_load() {
        use std::sync::{Arc, Barrier};
        use std::thread;
        use std::time::Duration;

        const NUM_THREADS: usize = 12;
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
                thread::sleep(Duration::from_millis((thread_id % 3) as u64));

                for iteration in 0..ITERATIONS_PER_THREAD {
                    let result = std::panic::catch_unwind(|| {
                        // Create multiple crypto contexts simultaneously
                        let (cc1, _key_pair1) = create_test_crypto_context_and_keypair();
                        let (cc2, _key_pair2) = create_test_crypto_context_and_keypair();

                        // Create many plaintexts rapidly
                        let mut plaintexts = Vec::new();
                        for i in 0..7 {
                            let value = (thread_id * 1000 + iteration * 10 + i) as i64;

                            // Single value plaintexts
                            plaintexts.push(create_test_plaintext_single(&cc1, value));
                            plaintexts.push(create_test_plaintext_single(&cc2, value));

                            // Vector plaintexts
                            let vector_vals = vec![value, value + 1, value + 2, value + 3];
                            plaintexts.push(create_test_plaintext_vector(&cc1, &vector_vals));
                            plaintexts.push(create_test_plaintext_vector(&cc2, &vector_vals));

                            // String plaintexts
                            let string_val =
                                format!("massive_load_{}_{}_{}_{}", thread_id, iteration, i, value);
                            plaintexts.push(create_test_plaintext_string(&cc1, &string_val));
                            plaintexts.push(create_test_plaintext_string(&cc2, &string_val));
                        }

                        // Perform massive operations on all plaintexts
                        for (i, pt) in plaintexts.iter().enumerate() {
                            // Basic operations
                            let len = pt.len();
                            let is_empty = pt.is_empty();
                            let string_repr = pt.get_string();
                            let debug_repr = format!("{:?}", pt);

                            // Consistency checks
                            assert_eq!(is_empty, len == 0);
                            assert!(!string_repr.is_empty());
                            assert!(!debug_repr.is_empty());
                            assert!(debug_repr.contains("Plaintext"));

                            // Get packed values for non-string plaintexts
                            if i % 3 != 0 {
                                // Skip every 3rd which might be string
                                let packed_values = pt.get_packed_value();
                                // Basic sanity check
                                if !packed_values.is_empty() {
                                    assert!(packed_values.len() > 0);
                                }
                            }
                        }

                        // Test mutable operations
                        let mut mutable_pts = Vec::new();
                        for i in 0..5 {
                            let mut pt = create_test_plaintext_single(&cc1, (i * 100) as i64);
                            let original_len = pt.len();

                            // Modify length
                            pt.set_length(original_len + i + 1);
                            assert_eq!(pt.len(), original_len + i + 1);

                            mutable_pts.push(pt);
                        }

                        // Cross-context operations (most likely to trigger segfaults)
                        for i in 0..plaintexts.len() {
                            for j in (i + 1)..plaintexts.len().min(i + 5) {
                                // Limit to avoid too many comparisons
                                let pt1 = &plaintexts[i];
                                let pt2 = &plaintexts[j];

                                // Compare lengths and properties
                                let _len1 = pt1.len();
                                let _len2 = pt2.len();
                                let _empty1 = pt1.is_empty();
                                let _empty2 = pt2.is_empty();

                                // String operations
                                let _str1 = pt1.get_string();
                                let _str2 = pt2.get_string();
                            }
                        }
                    });

                    if result.is_err() {
                        let mut counter = panic_counter_clone.lock().unwrap();
                        *counter += 1;
                        eprintln!(
                            "Massive plaintext load Thread {} panic at iteration {}: {:?}",
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
                    "Massive plaintext load Thread {} completed successfully",
                    thread_id
                );
            });

            handles.push(handle);
        }

        for (i, handle) in handles.into_iter().enumerate() {
            match handle.join() {
                Ok(_) => println!("Massive plaintext load Thread {} joined successfully", i),
                Err(e) => {
                    eprintln!("Massive plaintext load Thread {} panicked: {:?}", i, e);
                    let mut counter = panic_counter.lock().unwrap();
                    *counter += 1;
                }
            }
        }

        let final_panic_count = *panic_counter.lock().unwrap();

        if final_panic_count > 0 {
            panic!(
                "Massive concurrent plaintext load test detected {} panics/segfaults. This indicates serious thread safety issues!",
                final_panic_count
            );
        }

        println!("Massive concurrent plaintext load test completed successfully - no thread safety issues detected");
    }

    #[test]
    fn test_plaintext_edge_cases() {
        let (cc, _key_pair) = create_test_crypto_context_and_keypair();

        // Test with single zero
        let zero_pt = create_test_plaintext_single(&cc, 0);
        assert!(!zero_pt.is_empty());
        let zero_values = zero_pt.get_packed_value();
        assert!(!zero_values.is_empty());
        assert_eq!(zero_values[0], 0);

        // Note: Empty string test removed because OpenFHE cannot encode empty value vectors

        // Test with special characters
        let special_pt = create_test_plaintext_string(&cc, "!@#$%^&*()_+-=[]{}|;':\",./<>?");
        assert!(!special_pt.is_empty());
        let special_repr = special_pt.get_string();
        assert!(!special_repr.is_empty());

        // Test with large single value (but within plaintext modulus)
        let large_pt = create_test_plaintext_single(&cc, 65536);
        assert!(!large_pt.is_empty());
        let large_values = large_pt.get_packed_value();
        assert!(!large_values.is_empty());
        assert_eq!(large_values[0], 65536);
    }

    #[test]
    fn test_plaintext_length_consistency() {
        let (cc, _key_pair) = create_test_crypto_context_and_keypair();

        let values = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut plaintext = create_test_plaintext_vector(&cc, &values);

        let original_len = plaintext.len();
        assert!(original_len > 0);

        // Test increasing length
        plaintext.set_length(original_len + 10);
        assert_eq!(plaintext.len(), original_len + 10);

        // Test decreasing length
        plaintext.set_length(original_len - 1);
        assert_eq!(plaintext.len(), original_len - 1);

        // Test setting to zero (might be allowed)
        plaintext.set_length(0);
        assert_eq!(plaintext.len(), 0);
        assert!(plaintext.is_empty());

        // Reset to positive length
        plaintext.set_length(5);
        assert_eq!(plaintext.len(), 5);
        assert!(!plaintext.is_empty());
    }
}
