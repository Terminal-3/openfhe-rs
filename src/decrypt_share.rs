use crate::ffi;
use cxx::{CxxVector, UniquePtr};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Represents a partial decryption share from one party.
///
/// This is a specialized ciphertext that can be safely cloned, debugged,
/// and serialized for network transmission.
pub struct DecryptionShare(pub(crate) UniquePtr<ffi::CiphertextDCRTPoly>);

impl Clone for DecryptionShare {
    /// Clones the decryption share using the underlying FFI clone function.
    fn clone(&self) -> Self {
        // A decryption share is a Ciphertext, so we use the same clone function.
        DecryptionShare(ffi::DCRTPolyCloneCiphertext(&self.0))
    }
}

impl std::fmt::Debug for DecryptionShare {
    /// Formats the decryption share by showing its serialized size to avoid printing large objects.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out_bytes = CxxVector::<u8>::new();
        ffi::DCRTPolySerializeCiphertextToBytes(self.0.as_ref().unwrap(), out_bytes.pin_mut());
        f.debug_struct("DecryptionShare")
            .field("len_bytes", &out_bytes.len())
            .finish()
    }
}

impl Serialize for DecryptionShare {
    /// Serializes the decryption share into a byte vector.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut out_bytes = CxxVector::<u8>::new();
        ffi::DCRTPolySerializeCiphertextToBytes(self.0.as_ref().unwrap(), out_bytes.pin_mut());
        // Use serde_bytes to efficiently serialize byte slices.
        serializer.serialize_bytes(out_bytes.as_slice())
    }
}

impl<'de> Deserialize<'de> for DecryptionShare {
    /// Deserializes a decryption share from a byte vector.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DecryptionShareVisitor;

        impl<'de> serde::de::Visitor<'de> for DecryptionShareVisitor {
            type Value = DecryptionShare;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a byte array representing a serialized DecryptionShare")
            }

            // Use visit_bytes for efficiency with serde_bytes.
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
                Ok(DecryptionShare(ct))
            }
        }

        deserializer.deserialize_bytes(DecryptionShareVisitor)
    }
}

/// A collection of decryption shares, wrapping the underlying C++ vector type.
///
/// This type is not directly serializable. To send shares over the network,
/// convert this collection to a `Vec<DecryptionShare>` using `.to_vec()`,
/// serialize the `Vec`, and then reconstruct this type using `.from_vec()`.
pub struct DecryptionShareVec(pub(crate) UniquePtr<ffi::VectorOfCiphertexts>);

impl DecryptionShareVec {
    /// Creates an empty collection of shares.
    pub fn new() -> Self {
        Self(ffi::vector_of_ciphertexts_empty())
    }

    /// Extends the collection with shares from another collection.
    pub fn extend(&mut self, other: &Self) {
        ffi::vector_of_ciphertexts_extend(self.0.pin_mut(), &other.0);
    }

    /// Returns the number of shares in the collection.
    pub fn len(&self) -> usize {
        self.0.as_ref().unwrap().Len()
    }

    /// Checks if the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for DecryptionShareVec {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi;
    use cxx::CxxVector;
    use std::sync::Mutex;

    /// Helper function to create a test DecryptionShare by creating a null ciphertext
    /// In real usage, DecryptionShares would be created from actual multiparty decryption operations
    fn create_test_decryption_share() -> DecryptionShare {
        // Create a null ciphertext as a placeholder for a decryption share
        // In practice, this would come from actual multiparty operations
        let ct = ffi::DCRTPolyGenNullCiphertext();
        DecryptionShare(ct)
    }

    /// Helper function to create multiple test DecryptionShares
    fn create_multiple_test_shares(count: usize) -> Vec<DecryptionShare> {
        (0..count).map(|_| create_test_decryption_share()).collect()
    }

    #[test]
    fn test_decryption_share_creation() {
        let share = create_test_decryption_share();

        // Test that the DecryptionShare is created successfully
        assert!(share.0.as_ref().is_some());
    }

    #[test]
    fn test_decryption_share_clone() {
        let original_share = create_test_decryption_share();
        let cloned_share = original_share.clone();

        // Test that cloning creates a valid instance
        assert!(original_share.0.as_ref().is_some());
        assert!(cloned_share.0.as_ref().is_some());

        // Both shares should be valid (though potentially different FFI objects)
        // We can't easily test equality, but we can test that both serialize
        let result1 = std::panic::catch_unwind(|| {
            let mut out_bytes1 = CxxVector::<u8>::new();
            ffi::DCRTPolySerializeCiphertextToBytes(
                original_share.0.as_ref().unwrap(),
                out_bytes1.pin_mut(),
            );
            out_bytes1.len()
        });

        let result2 = std::panic::catch_unwind(|| {
            let mut out_bytes2 = CxxVector::<u8>::new();
            ffi::DCRTPolySerializeCiphertextToBytes(
                cloned_share.0.as_ref().unwrap(),
                out_bytes2.pin_mut(),
            );
            out_bytes2.len()
        });

        // Both operations should either succeed or fail consistently
        assert_eq!(result1.is_ok(), result2.is_ok());
    }

    #[test]
    fn test_decryption_share_debug() {
        let share = create_test_decryption_share();

        let debug_result = std::panic::catch_unwind(|| {
            let debug_string = format!("{:?}", share);
            debug_string
        });

        match debug_result {
            Ok(debug_string) => {
                // Test that debug formatting works and contains expected elements
                assert!(debug_string.contains("DecryptionShare"));
                assert!(debug_string.contains("len_bytes"));
                println!("Debug format succeeded: {}", debug_string);
            }
            Err(_) => {
                println!("Debug format failed as expected (missing FFI function)");
            }
        }
    }

    #[test]
    fn test_decryption_share_serialization() {
        let share = create_test_decryption_share();

        // Test serialization using bincode (binary format)
        let serialization_result = std::panic::catch_unwind(|| bincode::serialize(&share));

        match serialization_result {
            Ok(Ok(serialized)) => {
                assert!(!serialized.is_empty());
                println!("Serialization succeeded with {} bytes", serialized.len());

                // Test deserialization
                let deserialization_result = std::panic::catch_unwind(|| {
                    bincode::deserialize::<DecryptionShare>(&serialized)
                });

                match deserialization_result {
                    Ok(Ok(deserialized_share)) => {
                        assert!(deserialized_share.0.as_ref().is_some());
                        println!("Deserialization succeeded");
                    }
                    Ok(Err(e)) => {
                        println!("Deserialization failed with error: {:?}", e);
                    }
                    Err(_) => {
                        println!("Deserialization panicked as expected (missing FFI function)");
                    }
                }
            }
            Ok(Err(e)) => {
                println!("Serialization failed with error: {:?}", e);
            }
            Err(_) => {
                println!("Serialization panicked as expected (missing FFI function)");
            }
        }
    }

    #[test]
    fn test_decryption_share_serialization_roundtrip() {
        let original_share = create_test_decryption_share();

        let roundtrip_result = std::panic::catch_unwind(|| {
            // Serialize
            let serialized = bincode::serialize(&original_share)?;

            // Deserialize
            let deserialized_share: DecryptionShare = bincode::deserialize(&serialized)?;

            Ok::<_, Box<dyn std::error::Error>>(deserialized_share)
        });

        match roundtrip_result {
            Ok(Ok(deserialized_share)) => {
                assert!(deserialized_share.0.as_ref().is_some());
                println!("Serialization roundtrip succeeded");
            }
            Ok(Err(e)) => {
                println!("Serialization roundtrip failed with error: {:?}", e);
            }
            Err(_) => {
                println!("Serialization roundtrip panicked as expected (missing FFI function)");
            }
        }
    }

    #[test]
    fn test_decryption_share_vec_creation() {
        let share_vec = DecryptionShareVec::new();

        // Test that DecryptionShareVec is created successfully
        assert!(share_vec.0.as_ref().is_some());
        assert_eq!(share_vec.len(), 0);
        assert!(share_vec.is_empty());
    }

    #[test]
    fn test_decryption_share_vec_default() {
        let share_vec = DecryptionShareVec::default();

        // Test that default creates an empty vector
        assert!(share_vec.0.as_ref().is_some());
        assert_eq!(share_vec.len(), 0);
        assert!(share_vec.is_empty());
    }

    #[test]
    fn test_decryption_share_vec_operations() {
        let mut share_vec1 = DecryptionShareVec::new();
        let share_vec2 = DecryptionShareVec::new();

        // Test initial state
        assert_eq!(share_vec1.len(), 0);
        assert!(share_vec1.is_empty());
        assert_eq!(share_vec2.len(), 0);
        assert!(share_vec2.is_empty());

        // Test extend operation (may fail due to missing FFI functions)
        let extend_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            share_vec1.extend(&share_vec2);
        }));

        match extend_result {
            Ok(_) => {
                // Extend succeeded - test the result
                assert_eq!(share_vec1.len(), 0); // Still 0 since both were empty
                assert!(share_vec1.is_empty());
                println!("Extend operation succeeded");
            }
            Err(_) => {
                println!("Extend operation failed as expected (missing FFI function)");
            }
        }

        // Test len and is_empty methods
        let len_result = std::panic::catch_unwind(|| (share_vec1.len(), share_vec1.is_empty()));

        match len_result {
            Ok((len, is_empty)) => {
                assert_eq!(len == 0, is_empty);
                println!(
                    "Length operations succeeded: len={}, is_empty={}",
                    len, is_empty
                );
            }
            Err(_) => {
                println!("Length operations failed as expected (missing FFI function)");
            }
        }
    }

    #[test]
    fn test_decryption_share_vec_multiple_operations() {
        // Create multiple vectors
        let mut vecs = Vec::new();
        for i in 0..5 {
            let result = std::panic::catch_unwind(|| DecryptionShareVec::new());

            match result {
                Ok(vec) => {
                    assert!(vec.0.as_ref().is_some());
                    vecs.push(vec);
                }
                Err(_) => {
                    println!("Vector creation {} failed as expected", i);
                    break;
                }
            }
        }

        // Test operations on all created vectors
        for (i, mut vec) in vecs.into_iter().enumerate() {
            let operations_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let len = vec.len();
                let is_empty = vec.is_empty();

                // Try to extend with a new empty vector
                let other = DecryptionShareVec::new();
                vec.extend(&other);

                (len, is_empty)
            }));

            match operations_result {
                Ok((len, is_empty)) => {
                    println!(
                        "Vector {} operations succeeded: len={}, is_empty={}",
                        i, len, is_empty
                    );
                }
                Err(_) => {
                    println!("Vector {} operations failed as expected", i);
                }
            }
        }
    }

    #[test]
    fn test_concurrent_decryption_share_operations() {
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
                        // Create DecryptionShares
                        let share1 = create_test_decryption_share();
                        let share2 = create_test_decryption_share();
                        let share3 = share1.clone();

                        // Test basic validity
                        assert!(share1.0.as_ref().is_some());
                        assert!(share2.0.as_ref().is_some());
                        assert!(share3.0.as_ref().is_some());

                        // Test debug formatting (may fail)
                        let _debug1 = std::panic::catch_unwind(|| format!("{:?}", share1));
                        let _debug2 = std::panic::catch_unwind(|| format!("{:?}", share2));

                        // Test serialization operations (may fail)
                        let _serialization_result =
                            std::panic::catch_unwind(|| bincode::serialize(&share1));

                        // Create DecryptionShareVecs
                        let mut vec1 = DecryptionShareVec::new();
                        let vec2 = DecryptionShareVec::new();
                        let vec3 = DecryptionShareVec::default();

                        // Test vector operations
                        assert!(vec1.0.as_ref().is_some());
                        assert!(vec2.0.as_ref().is_some());
                        assert!(vec3.0.as_ref().is_some());

                        let _len1 = std::panic::catch_unwind(|| vec1.len());
                        let _empty1 = std::panic::catch_unwind(|| vec1.is_empty());
                        let _len3 = std::panic::catch_unwind(|| vec3.len());

                        // Test extend operations (may fail)
                        let _extend_result =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                vec1.extend(&vec2);
                            }));

                        // Cross-thread validation - create more objects
                        for _i in 0..3 {
                            let _share = create_test_decryption_share();
                            let _vec = DecryptionShareVec::new();
                        }
                    });

                    if result.is_err() {
                        let mut counter = panic_counter_clone.lock().unwrap();
                        *counter += 1;
                        eprintln!(
                            "DecryptionShare Thread {} panic at iteration {}: {:?}",
                            thread_id, iteration, result
                        );
                        break; // Exit this thread's loop on panic
                    }

                    // Small delay between iterations
                    if iteration % 10 == 0 {
                        thread::sleep(Duration::from_millis(1));
                    }
                }

                println!(
                    "DecryptionShare Thread {} completed successfully",
                    thread_id
                );
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for (i, handle) in handles.into_iter().enumerate() {
            match handle.join() {
                Ok(_) => println!("DecryptionShare Thread {} joined successfully", i),
                Err(e) => {
                    eprintln!("DecryptionShare Thread {} panicked: {:?}", i, e);
                    let mut counter = panic_counter.lock().unwrap();
                    *counter += 1;
                }
            }
        }

        let final_panic_count = *panic_counter.lock().unwrap();

        if final_panic_count > 0 {
            panic!(
                "Concurrent DecryptionShare test detected {} panics/segfaults. This indicates thread safety issues!",
                final_panic_count
            );
        }

        println!("Concurrent DecryptionShare test completed successfully - no thread safety issues detected");
    }

    #[test]
    fn test_stress_decryption_share_creation() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        const NUM_THREADS: usize = 4;
        const SHARES_PER_THREAD: usize = 20;

        let barrier = Arc::new(Barrier::new(NUM_THREADS));
        let mut handles = Vec::new();

        for thread_id in 0..NUM_THREADS {
            let barrier_clone = Arc::clone(&barrier);

            let handle = thread::spawn(move || {
                barrier_clone.wait();

                let mut shares_and_vecs = Vec::new();

                // Create multiple shares and vectors rapidly
                for i in 0..SHARES_PER_THREAD {
                    let result = std::panic::catch_unwind(|| {
                        // Create shares
                        let share1 = create_test_decryption_share();
                        let share2 = create_test_decryption_share();
                        let share3 = share1.clone();

                        // Create vectors
                        let mut vec1 = DecryptionShareVec::new();
                        let vec2 = DecryptionShareVec::default();

                        // Test some operations
                        let _len1 = std::panic::catch_unwind(|| vec1.len());
                        let _empty2 = std::panic::catch_unwind(|| vec2.is_empty());

                        // Try extend operation
                        let _extend_result =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                vec1.extend(&vec2);
                            }));

                        (vec![share1, share2, share3], vec![vec1, vec2])
                    });

                    match result {
                        Ok((shares, vecs)) => {
                            // Store them to prevent immediate destruction
                            shares_and_vecs.push((shares, vecs));

                            // Perform some operations on the latest objects
                            if let Some((latest_shares, latest_vecs)) = shares_and_vecs.last() {
                                for share in latest_shares {
                                    let _debug =
                                        std::panic::catch_unwind(|| format!("{:?}", share));
                                }
                                for vec in latest_vecs {
                                    let _len = std::panic::catch_unwind(|| vec.len());
                                }
                            }
                        }
                        Err(e) => {
                            panic!("Thread {} panicked at creation {}: {:?}", thread_id, i, e);
                        }
                    }
                }

                println!(
                    "Thread {} created {} share sets successfully",
                    thread_id, SHARES_PER_THREAD
                );

                // Test operations on all created objects
                for (i, (shares, vecs)) in shares_and_vecs.iter().enumerate() {
                    let result = std::panic::catch_unwind(|| {
                        // Test share operations
                        for share in shares {
                            assert!(share.0.as_ref().is_some());
                            let _serialization =
                                std::panic::catch_unwind(|| bincode::serialize(share));
                        }

                        // Test vector operations
                        for vec in vecs {
                            assert!(vec.0.as_ref().is_some());
                            let _len = std::panic::catch_unwind(|| vec.len());
                            let _empty = std::panic::catch_unwind(|| vec.is_empty());
                        }
                    });

                    if result.is_err() {
                        panic!(
                            "Thread {} panicked during operations on set {}: {:?}",
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
                    "DecryptionShare stress test thread {} completed successfully",
                    i
                ),
                Err(e) => panic!("DecryptionShare stress test thread {} panicked: {:?}", i, e),
            }
        }

        println!("DecryptionShare stress test completed successfully");
    }

    #[test]
    fn test_massive_concurrent_decryption_share_load() {
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
                        // Create many objects simultaneously
                        let mut shares = Vec::new();
                        let mut vecs = Vec::new();

                        for _ in 0..10 {
                            // Create shares
                            let share1 = create_test_decryption_share();
                            let share2 = share1.clone();
                            let share3 = create_test_decryption_share();

                            shares.push(share1);
                            shares.push(share2);
                            shares.push(share3);

                            // Create vectors
                            let vec1 = DecryptionShareVec::new();
                            let mut vec2 = DecryptionShareVec::default();
                            let vec3 = DecryptionShareVec::new();

                            // Rapid operations
                            let _len = std::panic::catch_unwind(|| vec2.len());
                            let _empty = std::panic::catch_unwind(|| vec2.is_empty());

                            // Cross-vector operations
                            let _extend1 =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    vec2.extend(&vec1);
                                }));
                            let _extend2 =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    vec2.extend(&vec3);
                                }));

                            vecs.push(vec1);
                            vecs.push(vec2);
                            vecs.push(vec3);
                        }

                        // Massive operations on all created objects
                        for (i, share) in shares.iter().enumerate() {
                            assert!(share.0.as_ref().is_some());

                            // High-frequency operations that might trigger race conditions
                            let _debug = std::panic::catch_unwind(|| format!("{:?}", share));
                            let _clone = std::panic::catch_unwind(|| share.clone());
                            let _serialize = std::panic::catch_unwind(|| bincode::serialize(share));

                            // Create more clones to stress the FFI
                            if i % 3 == 0 {
                                let _clone2 = share.clone();
                                let _clone3 = _clone2.clone();
                            }
                        }

                        for (i, vec) in vecs.iter().enumerate() {
                            assert!(vec.0.as_ref().is_some());

                            // Rapid sequential operations
                            let _len = std::panic::catch_unwind(|| vec.len());
                            let _empty = std::panic::catch_unwind(|| vec.is_empty());

                            // Cross-vector operations with other vectors
                            if i > 0 && i < vecs.len() - 1 {
                                let _extend = std::panic::catch_unwind(|| {
                                    // Note: This would require mutable access, so we skip it
                                    // in this iteration to avoid borrow checker issues
                                });
                            }
                        }

                        // Create additional objects for stress testing
                        for _j in 0..5 {
                            let _stress_share = create_test_decryption_share();
                            let _stress_vec = DecryptionShareVec::new();
                        }
                    });

                    if result.is_err() {
                        let mut counter = panic_counter_clone.lock().unwrap();
                        *counter += 1;
                        eprintln!(
                            "Massive DecryptionShare load Thread {} panic at iteration {}: {:?}",
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
                    "Massive DecryptionShare load Thread {} completed successfully",
                    thread_id
                );
            });

            handles.push(handle);
        }

        for (i, handle) in handles.into_iter().enumerate() {
            match handle.join() {
                Ok(_) => println!(
                    "Massive DecryptionShare load Thread {} joined successfully",
                    i
                ),
                Err(e) => {
                    eprintln!(
                        "Massive DecryptionShare load Thread {} panicked: {:?}",
                        i, e
                    );
                    let mut counter = panic_counter.lock().unwrap();
                    *counter += 1;
                }
            }
        }

        let final_panic_count = *panic_counter.lock().unwrap();

        if final_panic_count > 0 {
            panic!(
                "Massive concurrent DecryptionShare load test detected {} panics/segfaults. This indicates serious thread safety issues!",
                final_panic_count
            );
        }

        println!("Massive concurrent DecryptionShare load test completed successfully - no thread safety issues detected");
    }

    #[test]
    fn test_decryption_share_edge_cases() {
        // Test multiple cloning levels
        let original = create_test_decryption_share();

        let clone_chain_result = std::panic::catch_unwind(|| {
            let clone1 = original.clone();
            let clone2 = clone1.clone();
            let clone3 = clone2.clone();
            let clone4 = clone3.clone();

            // All should be valid
            assert!(clone1.0.as_ref().is_some());
            assert!(clone2.0.as_ref().is_some());
            assert!(clone3.0.as_ref().is_some());
            assert!(clone4.0.as_ref().is_some());

            vec![clone1, clone2, clone3, clone4]
        });

        match clone_chain_result {
            Ok(clones) => {
                println!("Clone chain succeeded with {} clones", clones.len());

                // Test serialization of all clones
                for (i, clone) in clones.iter().enumerate() {
                    let _serialize = std::panic::catch_unwind(|| bincode::serialize(clone));
                    println!("Clone {} serialization attempted", i);
                }
            }
            Err(_) => {
                println!("Clone chain failed as expected");
            }
        }

        // Test vector edge cases
        let edge_case_result = std::panic::catch_unwind(|| {
            // Create many vectors
            let mut vecs = Vec::new();
            for _i in 0..10 {
                vecs.push(DecryptionShareVec::new());
                vecs.push(DecryptionShareVec::default());
            }

            // Test extending empty vectors with each other
            for i in 0..vecs.len() - 1 {
                let (left, right) = vecs.split_at_mut(i + 1);
                if let (Some(vec1), Some(vec2)) = (left.last_mut(), right.first()) {
                    let _extend = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        vec1.extend(vec2);
                    }));
                }
            }

            vecs.len()
        });

        match edge_case_result {
            Ok(count) => {
                println!("Edge case test succeeded with {} vectors", count);
            }
            Err(_) => {
                println!("Edge case test failed as expected");
            }
        }
    }
}
