#pragma once

#include "SequenceContainers.h"
#include "SerialMode.h"


#include <string>
#include <vector>   // For std::vector
#include <cstdint>  // For uint8_t


namespace openfhe
{

class CiphertextDCRTPoly;
class CryptoContextDCRTPoly;
class PrivateKeyDCRTPoly;
class PublicKeyDCRTPoly;

// Ciphertext
[[nodiscard]] bool DCRTPolyDeserializeCiphertextFromFile(const std::string& ciphertextLocation,
    CiphertextDCRTPoly& ciphertext, const SerialMode serialMode);
[[nodiscard]] bool DCRTPolySerializeCiphertextToFile(const std::string& ciphertextLocation,
    const CiphertextDCRTPoly& ciphertext, const SerialMode serialMode);

[[nodiscard]] bool DCRTPolyDeserializeCiphertextFromBytes(const std::vector<uint8_t>& bytes,
    CiphertextDCRTPoly& ciphertext);
[[nodiscard]] bool DCRTPolySerializeCiphertextToBytes(
    const CiphertextDCRTPoly& ciphertext,
    std::vector<uint8_t>& out_bytes);



// CryptoContext
[[nodiscard]] bool DCRTPolyDeserializeCryptoContextFromFile(const std::string& ccLocation,
    CryptoContextDCRTPoly& cryptoContext, const SerialMode serialMode);
[[nodiscard]] bool DCRTPolySerializeCryptoContextToFile(const std::string& ccLocation,
    const CryptoContextDCRTPoly& cryptoContext, const SerialMode serialMode);


// EvalAutomorphismKey
[[nodiscard]] bool DCRTPolyDeserializeEvalMultKeyFromFile(const std::string& multKeyLocation,
    const SerialMode serialMode);
[[nodiscard]] bool DCRTPolySerializeEvalMultKeyByIdToFile(const std::string& multKeyLocation,
    const SerialMode serialMode, const std::string& id);
[[nodiscard]] bool DCRTPolySerializeEvalMultKeyToFile(const std::string& multKeyLocation,
    const CryptoContextDCRTPoly& cryptoContext, const SerialMode serialMode);

// EvalMultKey
[[nodiscard]] bool DCRTPolyDeserializeEvalAutomorphismKeyFromFile(
    const std::string& automorphismKeyLocation, const SerialMode serialMode);
[[nodiscard]] bool DCRTPolySerializeEvalAutomorphismKeyByIdToFile(
    const std::string& automorphismKeyLocation, const SerialMode serialMode,
    const std::string& id);
[[nodiscard]] bool DCRTPolySerializeEvalAutomorphismKeyToFile(
    const std::string& automorphismKeyLocation, const CryptoContextDCRTPoly& cryptoContext,
    const SerialMode serialMode);

// EvalSumKey
[[nodiscard]] bool DCRTPolyDeserializeEvalSumKeyFromFile(const std::string& sumKeyLocation,
    const SerialMode serialMode);
[[nodiscard]] bool DCRTPolySerializeEvalSumKeyByIdToFile(const std::string& sumKeyLocation,
    const SerialMode serialMode, const std::string& id);
[[nodiscard]] bool DCRTPolySerializeEvalSumKeyToFile(const std::string& sumKeyLocation,
    const CryptoContextDCRTPoly& cryptoContext, const SerialMode serialMode);

// PublicKey
[[nodiscard]] bool DCRTPolyDeserializePublicKeyFromFile(const std::string& publicKeyLocation,
    PublicKeyDCRTPoly& publicKey, const SerialMode serialMode);
[[nodiscard]] bool DCRTPolySerializePublicKeyToFile(const std::string& publicKeyLocation,
    const PublicKeyDCRTPoly& publicKey, const SerialMode serialMode);
[[nodiscard]] bool DCRTPolyDeserializePublicKeyFromBytes(const std::vector<uint8_t>& bytes,
    PublicKeyDCRTPoly& publicKey);
[[nodiscard]] bool DCRTPolySerializePublicKeyToBytes(const PublicKeyDCRTPoly& publicKey,
    std::vector<uint8_t>& out_bytes);

[[nodiscard]] bool DCRTPolyDeserializePrivateKeyFromFile(const std::string& privateKeyLocation,
    PrivateKeyDCRTPoly& privateKey, const SerialMode serialMode);
[[nodiscard]] bool DCRTPolySerializePrivateKeyToFile(const std::string& privateKeyLocation,
    const PrivateKeyDCRTPoly& cryptoContext, const SerialMode serialMode);
[[nodiscard]] bool DCRTPolyDeserializePrivateKeyFromBytes(const std::vector<uint8_t>& bytes,
    PrivateKeyDCRTPoly& privateKey);
[[nodiscard]] bool DCRTPolySerializePrivateKeyToBytes(const PrivateKeyDCRTPoly& privateKey,
    std::vector<uint8_t>& out_bytes);

// DecryptionShareVec
[[nodiscard]] bool DCRTPolyDeserializeDecryptionShareVecFromBytes(const std::vector<uint8_t>& bytes,
    VectorOfCiphertexts& decryptionShareVec);
[[nodiscard]] bool DCRTPolySerializeDecryptionShareVecToBytes(
    const VectorOfCiphertexts& decryptionShareVec, std::vector<uint8_t>& out_bytes);

// Plaintext
[[nodiscard]] bool DCRTPolyDeserializePlaintextFromBytes(const std::vector<uint8_t>& bytes,
    Plaintext& plaintext);
[[nodiscard]] bool DCRTPolySerializePlaintextToBytes(const Plaintext& plaintext,
    std::vector<uint8_t>& out_bytes);


} // openfhe
