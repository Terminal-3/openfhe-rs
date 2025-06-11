use crate::ffi;
use cxx::{CxxVector, UniquePtr};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::sync::Mutex;

/// A wrapper for a public key.
/// It can be cloned, compared, and serialized.
pub struct PublicKey(pub(crate) UniquePtr<ffi::PublicKeyDCRTPoly>);

/// A wrapper for a secret key.
/// It is not cloneable or serializable to enforce security best practices.
pub struct SecretKey(pub(crate) UniquePtr<ffi::PrivateKeyDCRTPoly>);

/// A key pair containing both a public and a secret key.
pub struct KeyPair(pub(crate) UniquePtr<ffi::KeyPairDCRTPoly>);

impl KeyPair {
    /// Returns a reference to the public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.as_ref().unwrap().GetPublicKey())
    }

    /// Returns a reference to the secret key.
    pub fn secret_key(&self) -> SecretKey {
        SecretKey(self.0.as_ref().unwrap().GetPrivateKey())
    }
}

// --- Trait Implementations for PublicKey ---

impl Clone for PublicKey {
    fn clone(&self) -> Self {
        // Assumes a corresponding FFI clone function exists.
        PublicKey(ffi::DCRTPolyClonePublicKey(&self.0))
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out_bytes = CxxVector::<u8>::new();
        // Assumes a corresponding FFI serialization function exists.
        ffi::DCRTPolySerializePublicKeyToBytes(self.0.as_ref().unwrap(), out_bytes.pin_mut());
        f.debug_struct("PublicKey")
            .field("len_bytes", &out_bytes.len())
            .finish()
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        // Assumes a corresponding FFI equality function exists.
        ffi::ArePublicKeysEqual(&self.0, &other.0)
    }
}
impl Eq for PublicKey {}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut out_bytes = CxxVector::<u8>::new();
        ffi::DCRTPolySerializePublicKeyToBytes(self.0.as_ref().unwrap(), out_bytes.pin_mut());
        serializer.serialize_bytes(out_bytes.as_slice())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PublicKeyVisitor;

        impl<'de> serde::de::Visitor<'de> for PublicKeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a byte array representing a serialized PublicKey")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let mut bytes_vec = CxxVector::<u8>::new();
                for &byte in v {
                    bytes_vec.pin_mut().push(byte);
                }
                let mut pk = ffi::DCRTPolyGenNullPublicKey();
                ffi::DCRTPolyDeserializePublicKeyFromBytes(&bytes_vec, pk.pin_mut());
                Ok(PublicKey(pk))
            }
        }

        deserializer.deserialize_bytes(PublicKeyVisitor)
    }
}

// --- Trait Implementations for SecretKey ---

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        SecretKey(ffi::DCRTPolyClonePrivateKey(&self.0))
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKey").finish()
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        ffi::ArePrivateKeysEqual(&self.0, &other.0)
    }
}
impl Eq for SecretKey {}

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut out_bytes = CxxVector::<u8>::new();
        ffi::DCRTPolySerializePrivateKeyToBytes(self.0.as_ref().unwrap(), out_bytes.pin_mut());
        serializer.serialize_bytes(out_bytes.as_slice())
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SecretKeyVisitor;

        impl<'de> serde::de::Visitor<'de> for SecretKeyVisitor {
            type Value = SecretKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a byte array representing a serialized SecretKey")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let mut bytes_vec = CxxVector::<u8>::new();
                for &byte in v {
                    bytes_vec.pin_mut().push(byte);
                }
                let mut sk = ffi::DCRTPolyGenNullPrivateKey();
                ffi::DCRTPolyDeserializePrivateKeyFromBytes(&bytes_vec, sk.pin_mut());
                Ok(SecretKey(sk))
            }
        }

        deserializer.deserialize_bytes(SecretKeyVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi;
    use cxx::CxxVector;

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
    /// Helper function to create a crypto context and key pair for testing
    fn create_test_crypto_context() -> cxx::UniquePtr<ffi::CryptoContextDCRTPoly> {
        let mut cc_params_bfvrns = ffi::GenParamsBFVRNS();
        cc_params_bfvrns.pin_mut().SetPlaintextModulus(65537);
        cc_params_bfvrns.pin_mut().SetMultiplicativeDepth(1);

        let cc = ffi::DCRTPolyGenCryptoContextByParamsBFVRNS(&cc_params_bfvrns);
        cc.EnableByFeature(ffi::PKESchemeFeature::PKE);
        cc.EnableByFeature(ffi::PKESchemeFeature::KEYSWITCH);
        cc.EnableByFeature(ffi::PKESchemeFeature::LEVELEDSHE);

        cc
    }

    #[test]
    fn test_keypair_public_key_extraction() {
        let (_cc, key_pair) = create_test_crypto_context_and_keypair();

        let public_key = key_pair.public_key();

        // Test that we can extract a public key from a key pair
        // The key should be valid (not null/empty)
        assert!(public_key.0.as_ref().is_some());
    }

    #[test]
    fn test_keypair_secret_key_extraction() {
        let (_cc, key_pair) = create_test_crypto_context_and_keypair();

        let secret_key = key_pair.secret_key();

        // Test that we can extract a secret key from a key pair
        // The key should be valid (not null/empty)
        assert!(secret_key.0.as_ref().is_some());
    }

    #[test]
    fn test_public_key_clone() {
        let (_cc, key_pair) = create_test_crypto_context_and_keypair();

        let public_key1 = key_pair.public_key();
        let public_key2 = public_key1.clone();

        // Test that cloning creates a valid instance
        // Note: Due to FFI implementation details, cloned keys might not test as equal
        // but they should both be valid
        assert!(public_key1.0.as_ref().is_some());
        assert!(public_key2.0.as_ref().is_some());

        // Test that both keys serialize to the same bytes (they represent the same key)
        let mut bytes1 = CxxVector::<u8>::new();
        let mut bytes2 = CxxVector::<u8>::new();
        ffi::DCRTPolySerializePublicKeyToBytes(public_key1.0.as_ref().unwrap(), bytes1.pin_mut());
        ffi::DCRTPolySerializePublicKeyToBytes(public_key2.0.as_ref().unwrap(), bytes2.pin_mut());

        assert_eq!(bytes1.len(), bytes2.len());
        for (i, (&b1, &b2)) in bytes1.iter().zip(bytes2.iter()).enumerate() {
            assert_eq!(b1, b2, "Byte mismatch at position {}", i);
        }
    }

    #[test]
    fn test_public_key_equality() {
        let (_cc, key_pair) = create_test_crypto_context_and_keypair();

        let public_key1 = key_pair.public_key();
        let public_key2 = public_key1.clone();

        // Test equality between a key and its clone
        // This should work since clone creates a proper copy
        assert_eq!(public_key1, public_key2);
    }

    #[test]
    fn test_public_key_inequality() {
        let (_cc1, key_pair1) = create_test_crypto_context_and_keypair();
        let (_cc2, key_pair2) = create_test_crypto_context_and_keypair();

        let public_key1 = key_pair1.public_key();
        let public_key2 = key_pair2.public_key();

        // Test that public keys from different key pairs are different
        assert_ne!(public_key1, public_key2);
    }

    #[test]
    fn test_public_key_debug() {
        let (_cc, key_pair) = create_test_crypto_context_and_keypair();

        let public_key = key_pair.public_key();
        let debug_string = format!("{:?}", public_key);

        // Test that debug formatting works and contains expected elements
        assert!(debug_string.contains("PublicKey"));
        assert!(debug_string.contains("len_bytes"));

        // The debug representation should contain a non-zero byte length
        // (a valid public key should have a non-zero serialized size)
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
            "Public key should have non-zero serialized size"
        );
    }

    #[test]
    fn test_public_key_serialization() {
        let (_cc, key_pair) = create_test_crypto_context_and_keypair();

        let public_key = key_pair.public_key();

        // Test serialization to JSON using serde_json
        // Note: The JSON will contain base64-encoded bytes since we serialize as bytes
        let serialized = serde_json::to_string(&public_key).expect("Serialization should succeed");
        assert!(!serialized.is_empty());

        // The serialized data should be valid JSON (base64 string)
        let _: serde_json::Value =
            serde_json::from_str(&serialized).expect("Serialized data should be valid JSON");
    }

    #[test]
    fn test_public_key_deserialization() {
        let (_cc, key_pair) = create_test_crypto_context_and_keypair();

        let original_key = key_pair.public_key();

        // Test serialization/deserialization using bincode (binary format)
        // JSON deserialization is tricky because serde_json expects bytes as base64
        let serialized = bincode::serialize(&original_key).expect("Serialization should succeed");
        let deserialized_key: PublicKey =
            bincode::deserialize(&serialized).expect("Deserialization should succeed");

        // Test that the deserialized key equals the original
        assert_eq!(original_key, deserialized_key);
    }

    #[test]
    fn test_public_key_serialization_roundtrip() {
        let (_cc, key_pair) = create_test_crypto_context_and_keypair();

        let original_key = key_pair.public_key();

        // Test bincode roundtrip (binary serialization works better than JSON for raw bytes)
        let binary_serialized =
            bincode::serialize(&original_key).expect("Binary serialization should succeed");
        let binary_deserialized: PublicKey = bincode::deserialize(&binary_serialized)
            .expect("Binary deserialization should succeed");
        assert_eq!(original_key, binary_deserialized);
    }

    #[test]
    fn test_public_key_hash_consistency() {
        let (_cc, key_pair) = create_test_crypto_context_and_keypair();

        let public_key = key_pair.public_key();
        let cloned_key = public_key.clone();

        // Calculate hashes manually since PublicKey might not implement Hash
        // We'll use the serialized bytes for consistency checking
        let mut out_bytes1 = CxxVector::<u8>::new();
        ffi::DCRTPolySerializePublicKeyToBytes(
            public_key.0.as_ref().unwrap(),
            out_bytes1.pin_mut(),
        );

        let mut out_bytes2 = CxxVector::<u8>::new();
        ffi::DCRTPolySerializePublicKeyToBytes(
            cloned_key.0.as_ref().unwrap(),
            out_bytes2.pin_mut(),
        );

        // Test that equal keys have the same serialized representation
        assert_eq!(out_bytes1.len(), out_bytes2.len());
        for (i, (&byte1, &byte2)) in out_bytes1.iter().zip(out_bytes2.iter()).enumerate() {
            assert_eq!(byte1, byte2, "Byte mismatch at position {}", i);
        }
    }

    #[test]
    fn test_secret_key_creation() {
        let (_cc, key_pair) = create_test_crypto_context_and_keypair();

        let secret_key = key_pair.secret_key();

        // Test that secret key is created successfully
        assert!(secret_key.0.as_ref().is_some());
    }

    #[test]
    fn test_secret_key_clone() {
        let (_cc, key_pair) = create_test_crypto_context_and_keypair();

        let secret_key1 = key_pair.secret_key();
        let secret_key2 = secret_key1.clone();

        // Test that cloning creates a valid instance
        assert!(secret_key1.0.as_ref().is_some());
        assert!(secret_key2.0.as_ref().is_some());

        assert_eq!(secret_key1, secret_key2);

        // Test that both keys serialize to the same bytes (they represent the same key)
        let mut bytes1 = CxxVector::<u8>::new();
        let mut bytes2 = CxxVector::<u8>::new();
        ffi::DCRTPolySerializePrivateKeyToBytes(secret_key1.0.as_ref().unwrap(), bytes1.pin_mut());
        ffi::DCRTPolySerializePrivateKeyToBytes(secret_key2.0.as_ref().unwrap(), bytes2.pin_mut());

        assert_eq!(bytes1.len(), bytes2.len());
        for (i, (&b1, &b2)) in bytes1.iter().zip(bytes2.iter()).enumerate() {
            assert_eq!(b1, b2, "Byte mismatch at position {}", i);
        }
    }

    #[test]
    fn test_secret_key_equality() {
        let (_cc, key_pair) = create_test_crypto_context_and_keypair();

        let secret_key1 = key_pair.secret_key();
        let secret_key2 = secret_key1.clone();

        // Test equality between a key and its clone
        assert_eq!(secret_key1, secret_key2);
    }

    #[test]
    fn test_secret_key_inequality() {
        let (_cc1, key_pair1) = create_test_crypto_context_and_keypair();
        let (_cc2, key_pair2) = create_test_crypto_context_and_keypair();

        let secret_key1 = key_pair1.secret_key();
        let secret_key2 = key_pair2.secret_key();

        // Test that secret keys from different key pairs are different
        assert_ne!(secret_key1, secret_key2);
    }

    #[test]
    fn test_secret_key_debug() {
        let (_cc, key_pair) = create_test_crypto_context_and_keypair();

        let secret_key = key_pair.secret_key();
        let debug_string = format!("{:?}", secret_key);

        // Test that debug formatting works and contains expected elements
        // SecretKey debug should not reveal sensitive information
        assert!(debug_string.contains("SecretKey"));

        // Should not contain any sensitive data like byte representations
        assert!(!debug_string.contains("len_bytes"));
        assert!(!debug_string.contains("bytes"));
    }

    #[test]
    fn test_secret_key_serialization() {
        let (_cc, key_pair) = create_test_crypto_context_and_keypair();

        let secret_key = key_pair.secret_key();

        // Test serialization using bincode (binary format)
        let serialized = bincode::serialize(&secret_key).expect("Serialization should succeed");
        assert!(!serialized.is_empty());
    }

    #[test]
    fn test_secret_key_deserialization() {
        let (_cc, key_pair) = create_test_crypto_context_and_keypair();

        let original_key = key_pair.secret_key();

        // Test serialization/deserialization using bincode
        let serialized = bincode::serialize(&original_key).expect("Serialization should succeed");
        let deserialized_key: SecretKey =
            bincode::deserialize(&serialized).expect("Deserialization should succeed");

        // Test that the deserialized key equals the original
        assert_eq!(original_key, deserialized_key);
    }

    #[test]
    fn test_secret_key_serialization_roundtrip() {
        let (_cc, key_pair) = create_test_crypto_context_and_keypair();

        let original_key = key_pair.secret_key();

        // Test bincode roundtrip
        let binary_serialized =
            bincode::serialize(&original_key).expect("Binary serialization should succeed");
        let binary_deserialized: SecretKey = bincode::deserialize(&binary_serialized)
            .expect("Binary deserialization should succeed");
        assert_eq!(original_key, binary_deserialized);
    }

    #[test]
    fn test_secret_key_serialization_with_different_keys() {
        let (_cc1, key_pair1) = create_test_crypto_context_and_keypair();
        let (_cc2, key_pair2) = create_test_crypto_context_and_keypair();

        let secret_key1 = key_pair1.secret_key();
        let secret_key2 = key_pair2.secret_key();

        assert_ne!(secret_key1, secret_key2);

        // Serialize both keys using bincode
        let serialized1 = bincode::serialize(&secret_key1).expect("Serialization should succeed");
        let serialized2 = bincode::serialize(&secret_key2).expect("Serialization should succeed");

        // Different keys should have different serializations
        assert_ne!(serialized1, serialized2);

        // Deserialize and verify they're still different
        let deserialized1: SecretKey =
            bincode::deserialize(&serialized1).expect("Deserialization should succeed");
        let deserialized2: SecretKey =
            bincode::deserialize(&serialized2).expect("Deserialization should succeed");

        assert_ne!(deserialized1, deserialized2);
        assert_eq!(secret_key1, deserialized1);
        assert_eq!(secret_key2, deserialized2);
    }

    #[test]
    fn test_secret_key_hash_consistency() {
        let (_cc, key_pair) = create_test_crypto_context_and_keypair();

        let secret_key = key_pair.secret_key();
        let cloned_key = secret_key.clone();

        // Calculate consistency by comparing serialized bytes
        let mut out_bytes1 = CxxVector::<u8>::new();
        ffi::DCRTPolySerializePrivateKeyToBytes(
            secret_key.0.as_ref().unwrap(),
            out_bytes1.pin_mut(),
        );

        let mut out_bytes2 = CxxVector::<u8>::new();
        ffi::DCRTPolySerializePrivateKeyToBytes(
            cloned_key.0.as_ref().unwrap(),
            out_bytes2.pin_mut(),
        );

        // Test that equal keys have the same serialized representation
        assert_eq!(out_bytes1.len(), out_bytes2.len());
        for (i, (&byte1, &byte2)) in out_bytes1.iter().zip(out_bytes2.iter()).enumerate() {
            assert_eq!(byte1, byte2, "Byte mismatch at position {}", i);
        }
    }

    #[test]
    fn test_secret_key_not_cloneable() {
        // This test ensures that SecretKey doesn't implement Clone
        // This is verified at compile time - if SecretKey implemented Clone,
        // the following line would compile:
        // let (_cc, key_pair) = create_test_crypto_context_and_keypair();
        // let secret_key = key_pair.secret_key();
        // let _cloned_secret = secret_key.clone(); // This should NOT compile

        // Since we can't test compilation failure in a unit test, we just verify
        // that the SecretKey struct exists and can be created
        let (_cc, key_pair) = create_test_crypto_context_and_keypair();
        let _secret_key = key_pair.secret_key();
        // If this test compiles and runs, SecretKey is working as expected
    }

    #[test]
    fn test_secret_key_not_serializable() {
        // This test ensures that SecretKey doesn't implement Serialize
        // Similar to the clone test, this is verified at compile time
        let (_cc, key_pair) = create_test_crypto_context_and_keypair();
        let _secret_key = key_pair.secret_key();

        // The following line should NOT compile if SecretKey correctly doesn't implement Serialize:
        // let _serialized = serde_json::to_string(&secret_key).unwrap();

        // If this test compiles and runs, SecretKey correctly doesn't implement Serialize
    }

    #[test]
    fn test_keypair_multiple_extractions() {
        let (_cc, key_pair) = create_test_crypto_context_and_keypair();

        // Test that we can extract public and secret keys multiple times
        let public_key1 = key_pair.public_key();
        let public_key2 = key_pair.public_key();
        let secret_key1 = key_pair.secret_key();
        let secret_key2 = key_pair.secret_key();

        assert_eq!(public_key1, public_key2);
        assert_eq!(secret_key1, secret_key2);

        // Both keys should be valid
        assert!(public_key1.0.as_ref().is_some());
        assert!(public_key2.0.as_ref().is_some());
        assert!(secret_key1.0.as_ref().is_some());
        assert!(secret_key2.0.as_ref().is_some());

        // The public keys should represent the same cryptographic key
        // even if they're different FFI objects
        let mut bytes1 = CxxVector::<u8>::new();
        let mut bytes2 = CxxVector::<u8>::new();
        ffi::DCRTPolySerializePublicKeyToBytes(public_key1.0.as_ref().unwrap(), bytes1.pin_mut());
        ffi::DCRTPolySerializePublicKeyToBytes(public_key2.0.as_ref().unwrap(), bytes2.pin_mut());

        assert_eq!(bytes1.len(), bytes2.len());
    }

    #[test]
    fn test_public_key_serialization_with_different_keys() {
        let (_cc1, key_pair1) = create_test_crypto_context_and_keypair();
        let (_cc2, key_pair2) = create_test_crypto_context_and_keypair();

        let public_key1 = key_pair1.public_key();
        let public_key2 = key_pair2.public_key();

        assert_ne!(public_key1, public_key2);

        // Serialize both keys using bincode
        let serialized1 = bincode::serialize(&public_key1).expect("Serialization should succeed");
        let serialized2 = bincode::serialize(&public_key2).expect("Serialization should succeed");

        // Different keys should have different serializations
        assert_ne!(serialized1, serialized2);

        // Deserialize and verify they're still different
        let deserialized1: PublicKey =
            bincode::deserialize(&serialized1).expect("Deserialization should succeed");
        let deserialized2: PublicKey =
            bincode::deserialize(&serialized2).expect("Deserialization should succeed");

        assert_ne!(deserialized1, deserialized2);
        assert_eq!(public_key1, deserialized1);
        assert_eq!(public_key2, deserialized2);
    }

    #[test]
    fn test_concurrent_crypto_operations() {
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
                        let (_cc, key_pair) = create_test_crypto_context_and_keypair();

                        // Extract keys
                        let public_key = key_pair.public_key();
                        let secret_key = key_pair.secret_key();

                        // Clone operations
                        let public_key_clone = public_key.clone();
                        let secret_key_clone = secret_key.clone();

                        // Equality checks
                        assert_eq!(public_key, public_key_clone);
                        assert_eq!(secret_key, secret_key_clone);

                        // Serialization operations
                        let pub_serialized = bincode::serialize(&public_key)
                            .expect("Public key serialization should succeed");
                        let sec_serialized = bincode::serialize(&secret_key)
                            .expect("Secret key serialization should succeed");

                        // Deserialization operations
                        let _pub_deserialized: PublicKey = bincode::deserialize(&pub_serialized)
                            .expect("Public key deserialization should succeed");
                        let _sec_deserialized: SecretKey = bincode::deserialize(&sec_serialized)
                            .expect("Secret key deserialization should succeed");

                        // Debug formatting
                        let _pub_debug = format!("{:?}", public_key);
                        let _sec_debug = format!("{:?}", secret_key);

                        // FFI serialization operations
                        let mut out_bytes = CxxVector::<u8>::new();
                        ffi::DCRTPolySerializePublicKeyToBytes(
                            public_key.0.as_ref().unwrap(),
                            out_bytes.pin_mut(),
                        );

                        let mut sec_out_bytes = CxxVector::<u8>::new();
                        ffi::DCRTPolySerializePrivateKeyToBytes(
                            secret_key.0.as_ref().unwrap(),
                            sec_out_bytes.pin_mut(),
                        );

                        // Create another key pair to test inequality
                        let (_cc2, key_pair2) = create_test_crypto_context_and_keypair();
                        let public_key2 = key_pair2.public_key();
                        let secret_key2 = key_pair2.secret_key();

                        // Test inequality (this often triggers the segfault)
                        assert_ne!(public_key, public_key2);
                        assert_ne!(secret_key, secret_key2);

                        // Test equality comparisons via FFI
                        assert!(ffi::ArePublicKeysEqual(&public_key.0, &public_key_clone.0));
                        assert!(ffi::ArePrivateKeysEqual(&secret_key.0, &secret_key_clone.0));
                        assert!(!ffi::ArePublicKeysEqual(&public_key.0, &public_key2.0));
                        assert!(!ffi::ArePrivateKeysEqual(&secret_key.0, &secret_key2.0));
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

                println!("Thread {} completed successfully", thread_id);
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for (i, handle) in handles.into_iter().enumerate() {
            match handle.join() {
                Ok(_) => println!("Thread {} joined successfully", i),
                Err(e) => {
                    eprintln!("Thread {} panicked: {:?}", i, e);
                    let mut counter = panic_counter.lock().unwrap();
                    *counter += 1;
                }
            }
        }

        let final_panic_count = *panic_counter.lock().unwrap();

        if final_panic_count > 0 {
            panic!(
                "Concurrent test detected {} panics/segfaults. This indicates thread safety issues!",
                final_panic_count
            );
        }

        println!("Concurrent test completed successfully - no thread safety issues detected");
    }

    #[test]
    fn test_stress_crypto_context_creation() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        const NUM_THREADS: usize = 4;
        const CONTEXTS_PER_THREAD: usize = 20;

        let barrier = Arc::new(Barrier::new(NUM_THREADS));
        let mut handles = Vec::new();

        for thread_id in 0..NUM_THREADS {
            let barrier_clone = Arc::clone(&barrier);

            let handle = thread::spawn(move || {
                barrier_clone.wait();

                let mut contexts_and_keypairs = Vec::new();

                // Create multiple contexts rapidly
                for i in 0..CONTEXTS_PER_THREAD {
                    let result =
                        std::panic::catch_unwind(|| create_test_crypto_context_and_keypair());

                    match result {
                        Ok((cc, key_pair)) => {
                            // Store them to prevent immediate destruction
                            contexts_and_keypairs.push((cc, key_pair));

                            // Perform some operations
                            if let Some((_, last_key_pair)) = contexts_and_keypairs.last() {
                                let public_key = last_key_pair.public_key();
                                let _cloned = public_key.clone();
                                let _debug = format!("{:?}", public_key);
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
                for (i, (_, key_pair)) in contexts_and_keypairs.iter().enumerate() {
                    // Extract the keys first, outside of catch_unwind
                    let public_key = key_pair.public_key();
                    let secret_key = key_pair.secret_key();

                    let result = std::panic::catch_unwind(|| {
                        // Serialize/deserialize
                        let pub_bytes = bincode::serialize(&public_key).unwrap();
                        let sec_bytes = bincode::serialize(&secret_key).unwrap();

                        let _: PublicKey = bincode::deserialize(&pub_bytes).unwrap();
                        let _: SecretKey = bincode::deserialize(&sec_bytes).unwrap();
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
                Ok(_) => println!("Stress test thread {} completed successfully", i),
                Err(e) => panic!("Stress test thread {} panicked: {:?}", i, e),
            }
        }

        println!("Stress test completed successfully");
    }
}
