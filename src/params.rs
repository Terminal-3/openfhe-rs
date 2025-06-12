use crate::ffi;
use cxx::UniquePtr;

/// A wrapper for BFV-RNS scheme parameters.
///
/// Encapsulates the configuration required to set up a `CryptoContext`.
pub struct Params(pub(crate) UniquePtr<ffi::ParamsBFVRNS>);

impl Params {
    /// Creates a new set of BFV-RNS parameters.
    pub fn new() -> Self {
        Params(ffi::GenParamsBFVRNS())
    }

    /// Sets the plaintext modulus.
    pub fn set_plaintext_modulus(&mut self, modulus: u64) {
        self.0.as_mut().unwrap().SetPlaintextModulus(modulus);
    }

    /// Sets the batch size for packed encoding.
    pub fn set_batch_size(&mut self, batch_size: u32) {
        self.0.as_mut().unwrap().SetBatchSize(batch_size);
    }

    /// Configures the multiparty mode.
    pub fn set_multiparty_mode(&mut self, mode: ffi::MultipartyMode) {
        self.0.as_mut().unwrap().SetMultipartyMode(mode);
    }

    /// Sets the multiplicative depth.
    pub fn set_multiplicative_depth(&mut self, depth: usize) {
        self.0
            .as_mut()
            .unwrap()
            .SetMultiplicativeDepth(depth.try_into().unwrap());
    }
}

impl Default for Params {
    fn default() -> Self {
        let mut params = Self::new();
        params.set_plaintext_modulus(65537);
        // params.set_ring_dim(512); // Note: SetRingDim not available in wrapper yet
        params.set_batch_size(1);
        params.set_multiplicative_depth(0);
        // Note: Arguably we don't need noise flooding in TEE execution
        // without setting noise flooding the size of cyphertext drops from 380Kb to 60 Kb
        // params.set_multiparty_mode(ffi::MultipartyMode::NOISE_FLOODING_MULTIPARTY);
        params
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    // Helper function to create a basic params instance for testing
    fn create_test_params() -> Params {
        Params::new()
    }

    #[test]
    fn test_params_creation() {
        let params = Params::new();
        assert!(params.0.as_ref().is_some());
    }

    #[test]
    fn test_params_default() {
        let params = Params::default();
        assert!(params.0.as_ref().is_some());
    }

    #[test]
    fn test_set_plaintext_modulus() {
        let mut params = create_test_params();
        params.set_plaintext_modulus(65537);
        // If we reach here without panic, the method worked
        assert!(params.0.as_ref().is_some());
    }

    #[test]
    fn test_set_plaintext_modulus_multiple_values() {
        let mut params = create_test_params();

        // Test various valid modulus values
        let test_values = [2, 17, 65537, 1048583, 2097169];
        for &modulus in &test_values {
            params.set_plaintext_modulus(modulus);
            assert!(params.0.as_ref().is_some());
        }
    }

    #[test]
    fn test_set_batch_size() {
        let mut params = create_test_params();
        params.set_batch_size(8);
        assert!(params.0.as_ref().is_some());
    }

    #[test]
    fn test_set_batch_size_multiple_values() {
        let mut params = create_test_params();

        // Test various batch sizes
        let test_values = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];
        for &batch_size in &test_values {
            params.set_batch_size(batch_size);
            assert!(params.0.as_ref().is_some());
        }
    }

    #[test]
    fn test_set_multiplicative_depth() {
        let mut params = create_test_params();
        params.set_multiplicative_depth(2);
        assert!(params.0.as_ref().is_some());
    }

    #[test]
    fn test_set_multiplicative_depth_multiple_values() {
        let mut params = create_test_params();

        // Test various multiplicative depths
        let test_values = [0, 1, 2, 5, 10, 20];
        for &depth in &test_values {
            params.set_multiplicative_depth(depth);
            assert!(params.0.as_ref().is_some());
        }
    }

    #[test]
    fn test_set_multiparty_mode() {
        let mut params = create_test_params();
        params.set_multiparty_mode(ffi::MultipartyMode::FIXED_NOISE_MULTIPARTY);
        assert!(params.0.as_ref().is_some());
    }

    #[test]
    fn test_set_multiparty_mode_all_variants() {
        let mut params = create_test_params();

        // Test all multiparty mode variants
        let modes = [
            ffi::MultipartyMode::INVALID_MULTIPARTY_MODE,
            ffi::MultipartyMode::FIXED_NOISE_MULTIPARTY,
            ffi::MultipartyMode::NOISE_FLOODING_MULTIPARTY,
        ];

        for &mode in &modes {
            params.set_multiparty_mode(mode);
            assert!(params.0.as_ref().is_some());
        }
    }

    #[test]
    fn test_chained_parameter_setting() {
        let mut params = create_test_params();

        // Test setting multiple parameters in sequence
        params.set_plaintext_modulus(65537);
        params.set_batch_size(8);
        params.set_multiplicative_depth(2);
        params.set_multiparty_mode(ffi::MultipartyMode::FIXED_NOISE_MULTIPARTY);

        assert!(params.0.as_ref().is_some());
    }

    #[test]
    fn test_parameter_override() {
        let mut params = create_test_params();

        // Test overriding parameters multiple times
        params.set_plaintext_modulus(17);
        params.set_plaintext_modulus(65537);

        params.set_batch_size(4);
        params.set_batch_size(8);

        params.set_multiplicative_depth(1);
        params.set_multiplicative_depth(2);

        assert!(params.0.as_ref().is_some());
    }

    // Parallel tests for race condition detection
    #[test]
    fn test_parallel_params_creation() {
        const NUM_THREADS: usize = 10;
        const ITERATIONS_PER_THREAD: usize = 100;

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                thread::spawn(|| {
                    for _ in 0..ITERATIONS_PER_THREAD {
                        let params = Params::new();
                        assert!(params.0.as_ref().is_some());
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_parallel_params_default() {
        const NUM_THREADS: usize = 10;
        const ITERATIONS_PER_THREAD: usize = 100;

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                thread::spawn(|| {
                    for _ in 0..ITERATIONS_PER_THREAD {
                        let params = Params::default();
                        assert!(params.0.as_ref().is_some());
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_parallel_plaintext_modulus_setting() {
        const NUM_THREADS: usize = 8;
        const ITERATIONS_PER_THREAD: usize = 50;

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|thread_id| {
                thread::spawn(move || {
                    for i in 0..ITERATIONS_PER_THREAD {
                        let mut params = Params::new();
                        // Use different modulus values per thread to avoid conflicts
                        let modulus = match thread_id % 4 {
                            0 => 17,
                            1 => 65537,
                            2 => 1048583,
                            _ => 2097169,
                        };
                        params.set_plaintext_modulus(modulus + (i as u64));
                        assert!(params.0.as_ref().is_some());
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_parallel_batch_size_setting() {
        const NUM_THREADS: usize = 8;
        const ITERATIONS_PER_THREAD: usize = 50;

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|thread_id| {
                thread::spawn(move || {
                    for i in 0..ITERATIONS_PER_THREAD {
                        let mut params = Params::new();
                        // Use different batch sizes per thread
                        let batch_size = 2_u32.pow((thread_id % 8) as u32) * (i as u32 + 1);
                        params.set_batch_size(batch_size);
                        assert!(params.0.as_ref().is_some());
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_parallel_multiplicative_depth_setting() {
        const NUM_THREADS: usize = 8;
        const ITERATIONS_PER_THREAD: usize = 50;

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|thread_id| {
                thread::spawn(move || {
                    for i in 0..ITERATIONS_PER_THREAD {
                        let mut params = Params::new();
                        let depth = (thread_id + i) % 20; // Depths 0-19
                        params.set_multiplicative_depth(depth);
                        assert!(params.0.as_ref().is_some());
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_parallel_multiparty_mode_setting() {
        const NUM_THREADS: usize = 6;
        const ITERATIONS_PER_THREAD: usize = 50;

        let modes = [
            ffi::MultipartyMode::INVALID_MULTIPARTY_MODE,
            ffi::MultipartyMode::FIXED_NOISE_MULTIPARTY,
            ffi::MultipartyMode::NOISE_FLOODING_MULTIPARTY,
        ];

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|thread_id| {
                thread::spawn(move || {
                    for i in 0..ITERATIONS_PER_THREAD {
                        let mut params = Params::new();
                        let mode = modes[(thread_id + i) % modes.len()];
                        params.set_multiparty_mode(mode);
                        assert!(params.0.as_ref().is_some());
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_parallel_mixed_parameter_setting() {
        const NUM_THREADS: usize = 12;
        const ITERATIONS_PER_THREAD: usize = 25;

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|thread_id| {
                thread::spawn(move || {
                    for i in 0..ITERATIONS_PER_THREAD {
                        let mut params = Params::new();

                        // Set different combinations of parameters per thread
                        match thread_id % 4 {
                            0 => {
                                params.set_plaintext_modulus(65537 + i as u64);
                                params.set_batch_size((1 << (i % 8)) as u32);
                            }
                            1 => {
                                params.set_multiplicative_depth(i % 10);
                                params.set_multiparty_mode(
                                    ffi::MultipartyMode::FIXED_NOISE_MULTIPARTY,
                                );
                            }
                            2 => {
                                params.set_plaintext_modulus(1048583);
                                params.set_multiplicative_depth(i % 5);
                                params.set_batch_size(16);
                            }
                            _ => {
                                params.set_batch_size(8);
                                params.set_plaintext_modulus(17);
                                params.set_multiplicative_depth(2);
                                params.set_multiparty_mode(
                                    ffi::MultipartyMode::NOISE_FLOODING_MULTIPARTY,
                                );
                            }
                        }

                        assert!(params.0.as_ref().is_some());
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_synchronized_params_creation() {
        const NUM_THREADS: usize = 16;
        const ITERATIONS_PER_THREAD: usize = 20;

        let barrier = Arc::new(Barrier::new(NUM_THREADS));

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    for _ in 0..ITERATIONS_PER_THREAD {
                        // Synchronize all threads to create params at the same time
                        barrier.wait();
                        let params = Params::new();
                        assert!(params.0.as_ref().is_some());
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_synchronized_mixed_operations() {
        const NUM_THREADS: usize = 8;
        const ITERATIONS_PER_THREAD: usize = 30;

        let barrier = Arc::new(Barrier::new(NUM_THREADS));

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|thread_id| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    for i in 0..ITERATIONS_PER_THREAD {
                        // Synchronize all threads
                        barrier.wait();

                        let mut params = Params::new();

                        // Perform different operations based on thread_id
                        match thread_id % 4 {
                            0 => params.set_plaintext_modulus(65537 + i as u64),
                            1 => params.set_batch_size(1 << (i % 8)),
                            2 => params.set_multiplicative_depth(i % 15),
                            _ => params.set_multiparty_mode(if i % 2 == 0 {
                                ffi::MultipartyMode::FIXED_NOISE_MULTIPARTY
                            } else {
                                ffi::MultipartyMode::NOISE_FLOODING_MULTIPARTY
                            }),
                        }

                        assert!(params.0.as_ref().is_some());
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_high_frequency_params_creation() {
        const NUM_THREADS: usize = 20;
        const ITERATIONS_PER_THREAD: usize = 100;

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                thread::spawn(|| {
                    for _ in 0..ITERATIONS_PER_THREAD {
                        let params1 = Params::new();
                        let params2 = Params::default();
                        assert!(params1.0.as_ref().is_some());
                        assert!(params2.0.as_ref().is_some());
                        // Create and immediately drop to test memory management
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_stress_parameter_setting() {
        const NUM_THREADS: usize = 8;
        const ITERATIONS_PER_THREAD: usize = 200;

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|thread_id| {
                thread::spawn(move || {
                    for i in 0..ITERATIONS_PER_THREAD {
                        let mut params = Params::new();

                        // Rapidly set all parameters multiple times
                        for j in 0..5 {
                            params.set_plaintext_modulus(65537 + (i * j) as u64);
                            params.set_batch_size(1 << ((i + j + thread_id) % 8));
                            params.set_multiplicative_depth((i + j) % 10);
                            params.set_multiparty_mode(if (i + j) % 2 == 0 {
                                ffi::MultipartyMode::FIXED_NOISE_MULTIPARTY
                            } else {
                                ffi::MultipartyMode::NOISE_FLOODING_MULTIPARTY
                            });
                        }

                        assert!(params.0.as_ref().is_some());
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }
}
