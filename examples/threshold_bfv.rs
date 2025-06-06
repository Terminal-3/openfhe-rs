// examples/threshold_decrypt.rs
use openfhe::cxx::{CxxVector, UniquePtr};
use openfhe::ffi;

fn main() {
    // 1) Setup BFV‐RNS context with multiparty enabled
    let mut params: UniquePtr<ffi::ParamsBFVRNS> = ffi::GenParamsBFVRNS();

    // If SetPlaintextModulus is on the base Params class, you might need to cast or
    // have a specific method for ParamsBFVRNS
    params.as_mut().unwrap().SetPlaintextModulus(65537);
    params.as_mut().unwrap().SetBatchSize(16);
    params.as_mut().unwrap().SetMultiplicativeDepth(2);
    params
        .as_mut()
        .unwrap()
        .SetMultipartyMode(ffi::MultipartyMode::NOISE_FLOODING_MULTIPARTY);

    let mut cc: UniquePtr<ffi::CryptoContextDCRTPoly> =
        ffi::DCRTPolyGenCryptoContextByParamsBFVRNS(&params);

    for &feat in &[
        ffi::PKESchemeFeature::PKE,
        ffi::PKESchemeFeature::KEYSWITCH,
        ffi::PKESchemeFeature::MULTIPARTY,
    ] {
        cc.as_mut().unwrap().EnableByFeature(feat);
    }

    // 2) Party A: local key‐pair
    let kp1: UniquePtr<ffi::KeyPairDCRTPoly> = cc.as_ref().unwrap().KeyGen();
    let sk1 = kp1.as_ref().unwrap().GetPrivateKey();
    let pk1 = kp1.as_ref().unwrap().GetPublicKey();

    // 3) Party B: join using A's public key
    let kp2: UniquePtr<ffi::KeyPairDCRTPoly> = cc
        .as_ref()
        .unwrap()
        .MultipartyKeyGenByPublicKey(&pk1, false, false);
    let sk2 = kp2.as_ref().unwrap().GetPrivateKey();
    let pk2 = kp2.as_ref().unwrap().GetPublicKey();

    let data = vec![42i64, 7, 13];
    let mut data_vec = CxxVector::<i64>::new();
    for &x in &data {
        data_vec.pin_mut().push(x);
    }
    let pt: UniquePtr<ffi::Plaintext> = cc.as_ref().unwrap().MakePackedPlaintext(&data_vec, 1, 0);

    // 5) Encrypt under the *joint* public key
    let ct: UniquePtr<ffi::CiphertextDCRTPoly> = cc.as_ref().unwrap().EncryptByPublicKey(&pk2, &pt);
    let ct_ref = ct.as_ref().unwrap().GetRef();

    // 6) Create a vector for the single ciphertext (for multiparty decrypt)
    let enc_vec = ffi::vector_of_ciphertexts_single(&ct_ref);

    let share1 = cc.as_ref().unwrap().MultipartyDecryptLead(&enc_vec, &sk1);
    let share2 = cc.as_ref().unwrap().MultipartyDecryptMain(&enc_vec, &sk2);

    // Append the contents of share1 and share2 to parts
    let mut parts = ffi::vector_of_ciphertexts_empty();
    ffi::vector_of_ciphertexts_extend(parts.pin_mut(), &share1);
    ffi::vector_of_ciphertexts_extend(parts.pin_mut(), &share2);

    let mut out = ffi::GenNullPlainText();
    cc.as_mut()
        .unwrap()
        .MultipartyDecryptFusion(&parts, out.pin_mut());

    // 8) Display the recovered vector
    out.SetLength(data.len());
    println!("Decrypted → {}", out.GetString());
}
