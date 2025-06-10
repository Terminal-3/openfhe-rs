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

    /// Sets the multiplicative depth.
    pub fn set_multiplicative_depth(&mut self, depth: usize) {
        self.0
            .as_mut()
            .unwrap()
            .SetMultiplicativeDepth(depth.try_into().unwrap());
    }

    /// Configures the multiparty mode.
    pub fn set_multiparty_mode(&mut self, mode: ffi::MultipartyMode) {
        self.0.as_mut().unwrap().SetMultipartyMode(mode);
    }
}

impl Default for Params {
    fn default() -> Self {
        Self::new()
    }
}
