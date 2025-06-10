// examples/threshold_decrypt.rs
use openfhe::cxx::{CxxVector, UniquePtr};
use openfhe::ffi;

fn main() {
    // 1) Setup BFV‐RNS context with multiparty enabled
    let mut params: UniquePtr<ffi::ParamsBFVRNS> = ffi::GenParamsBFVRNS();

    // If SetPlaintextModulus is on the base Params class, you might need to cast or
    // have a specific method for ParamsBFVRNS
    params.as_mut().unwrap().SetPlaintextModulus(65537);
    // params.as_mut().unwrap().SetRingDim(512);
    params.as_mut().unwrap().SetBatchSize(1);
    params.as_mut().unwrap().SetMultiplicativeDepth(0);
    params.as_mut().unwrap().SetKeySwitchCount(0);
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
    let pk1: UniquePtr<ffi::PublicKeyDCRTPoly> = kp1.as_ref().unwrap().GetPublicKey();

    // 3) Party B: join using A's public key
    let kp2: UniquePtr<ffi::KeyPairDCRTPoly> = cc
        .as_ref()
        .unwrap()
        .MultipartyKeyGenByPublicKey(&pk1, false, false);
    let sk2 = kp2.as_ref().unwrap().GetPrivateKey();
    let pk2 = kp2.as_ref().unwrap().GetPublicKey();

    let data = vec![
        42i64, 7, 13, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101,
        103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
        197, 199, 211, 223, 227, 229,
    ];
    println!("data len → {:?}", data.len());
    println!("data → {:?}", data);
    let mut data_vec = CxxVector::<i64>::new();
    for &x in &data {
        data_vec.pin_mut().push(x);
    }
    let pt: UniquePtr<ffi::Plaintext> = cc.as_ref().unwrap().MakePackedPlaintext(&data_vec, 1, 0);

    // 5) Encrypt under the *joint* public key
    let ct: UniquePtr<ffi::CiphertextDCRTPoly> = cc.as_ref().unwrap().EncryptByPublicKey(&pk2, &pt);

    let mut out_bytes = CxxVector::<u8>::new();
    ffi::DCRTPolySerializeCiphertextToBytes(ct.as_ref().unwrap(), out_bytes.pin_mut());
    println!(
        "Serialized ciphertext len: {:?} kB",
        out_bytes.len() as f64 / 1024.0
    );

    let mut ct_deserialized = ffi::DCRTPolyGenNullCiphertext();
    ffi::DCRTPolyDeserializeCiphertextFromBytes(&out_bytes, ct_deserialized.pin_mut());

    // let's compare the ciphertexts
    let are_equal =
        ffi::AreCiphertextsEqual(ct.as_ref().unwrap(), ct_deserialized.as_ref().unwrap());
    println!("Are ciphertexts equal: {:?}", are_equal);

    let ct_ref = ct_deserialized.as_ref().unwrap().GetRef();

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

    println!("Decrypted len → {:?}", out.GetLength());
    println!("Decrypted → {}", out.GetString());
    // 8) Display the recovered vector
    out.SetLength(data.len());
    println!("Decrypted len → {:?}", out.GetLength());
    println!("Decrypted → {}", out.GetString());

    // assert that the decrypted data is equal to the original data
    assert_eq!(data, out.GetPackedValue().as_slice());
}
