#include "SerialDeserial.h"

#include "openfhe/pke/cryptocontext-ser.h"

#include "Ciphertext.h"
#include "CryptoContext.h"
#include "PrivateKey.h"
#include "PublicKey.h"

#include <sstream>

namespace openfhe
{

template <typename ST, typename Object>
[[nodiscard]] bool SerialDeserial(const std::string& location,
    bool (* const funcPtr) (const std::string&, Object&, const ST&), Object& object)
{
    return funcPtr(location, object, ST{});
}
template <typename Object>
[[nodiscard]] bool Deserial(const std::string& location, Object& object,
    const SerialMode serialMode)
{
    if (serialMode == SerialMode::BINARY)
    {
        return SerialDeserial<lbcrypto::SerType::SERBINARY, decltype(object.GetRef())>(location,
            lbcrypto::Serial::DeserializeFromFile, object.GetRef());
    }
    if (serialMode == SerialMode::JSON)
    {
        return SerialDeserial<lbcrypto::SerType::SERJSON, decltype(object.GetRef())>(location,
            lbcrypto::Serial::DeserializeFromFile, object.GetRef());
    }
    return false;
}
template <typename Object>
[[nodiscard]] bool Serial(const std::string& location, Object& object, const SerialMode serialMode)
{
    if (serialMode == SerialMode::BINARY)
    {
        return SerialDeserial<lbcrypto::SerType::SERBINARY, decltype(object.GetRef())>(location,
            lbcrypto::Serial::SerializeToFile, object.GetRef());
    }
    if (serialMode == SerialMode::JSON)
    {
        return SerialDeserial<lbcrypto::SerType::SERJSON, decltype(object.GetRef())>(location,
            lbcrypto::Serial::SerializeToFile, object.GetRef());
    }
    return false;
}

template <typename ST, typename Stream, typename FStream, typename... Types>
[[nodiscard]] bool SerialDeserial(const std::string& location,
    bool (* const funcPtr) (Stream&, const ST&, Types... args), Types... args)
{
    const auto close = [](FStream* const fs){ if (fs->is_open()) { fs->close(); } };
    const std::unique_ptr<FStream, decltype(close)> fs(
        new FStream(location, std::ios::binary), close);
    return fs->is_open() ? funcPtr(*fs, ST{}, args...) : false;
}


bool DCRTPolyDeserializeCiphertextFromBytes(const std::vector<uint8_t>& bytes,
    CiphertextDCRTPoly& ciphertext)
{
    try {
        std::string byte_string(bytes.begin(), bytes.end());
        std::stringstream stream(byte_string);
        lbcrypto::Serial::Deserialize(ciphertext.GetRef(), stream, lbcrypto::SerType::SERBINARY());
        return true; // Success
    } catch (const std::exception& e) {
        // TODO: could log the error here if there isa logging mechanism
        // std::cerr << "Deserialization failed: " << e.what() << std::endl;
        return false; // Failure
    }
}

bool DCRTPolySerializeCiphertextToBytes(const CiphertextDCRTPoly& ciphertext,
    std::vector<uint8_t>& out_bytes)
{
    // 1. Create an in-memory output string stream. This object behaves like
    //    std::cout or a file stream, but it writes data to an internal string buffer.
    std::ostringstream stream;

    try {

        // Call the library's serialization function. It will write the binary
        lbcrypto::Serial::Serialize(ciphertext.GetRef(), stream, lbcrypto::SerType::SERBINARY());
        // Extract the contents of the stream into a std::string. This copies the bytes exactly and there is no
        // guarantee about valid utf-8 unlike in other programming languages.
        // in C++20 there is a better method to do this without copying the bytes which is stream.view()
        std::string str = stream.str();
        out_bytes.assign(str.begin(), str.end());
        return true;
    } catch (const std::exception& e) {
        // TODO: could log the error here if there is a logging mechanism
        // std::cerr << "Serialization failed: " << e.what() << std::endl;
        return false; // Failure
    }

}




// Ciphertext
bool DCRTPolyDeserializeCiphertextFromFile(const std::string& ciphertextLocation,
    CiphertextDCRTPoly& ciphertext, const SerialMode serialMode)
{
    return Deserial(ciphertextLocation, ciphertext, serialMode);
}
bool DCRTPolySerializeCiphertextToFile(const std::string& ciphertextLocation,
    const CiphertextDCRTPoly& ciphertext, const SerialMode serialMode)
{
    return Serial(ciphertextLocation, ciphertext, serialMode);
}

// CryptoContext
bool DCRTPolyDeserializeCryptoContextFromFile(const std::string& ccLocation,
    CryptoContextDCRTPoly& cryptoContext, const SerialMode serialMode)
{
    return Deserial(ccLocation, cryptoContext, serialMode);
}
bool DCRTPolySerializeCryptoContextToFile(const std::string& ccLocation,
    const CryptoContextDCRTPoly& cryptoContext, const SerialMode serialMode)
{
    return Serial(ccLocation, cryptoContext, serialMode);
}

// EvalAutomorphismKey
bool DCRTPolyDeserializeEvalAutomorphismKeyFromFile(const std::string& automorphismKeyLocation,
    const SerialMode serialMode)
{
    if (serialMode == SerialMode::BINARY)
    {
        return SerialDeserial<lbcrypto::SerType::SERBINARY, std::istream, std::ifstream>(
            automorphismKeyLocation, CryptoContextImpl::DeserializeEvalAutomorphismKey);
    }
    if (serialMode == SerialMode::JSON)
    {
        return SerialDeserial<lbcrypto::SerType::SERJSON, std::istream, std::ifstream>(
            automorphismKeyLocation, CryptoContextImpl::DeserializeEvalAutomorphismKey);
    }
    return false;
}
bool DCRTPolySerializeEvalAutomorphismKeyByIdToFile(const std::string& automorphismKeyLocation,
    const SerialMode serialMode, const std::string& id)
{
    if (serialMode == SerialMode::BINARY)
    {
        return SerialDeserial<lbcrypto::SerType::SERBINARY, std::ostream, std::ofstream>(
            automorphismKeyLocation, CryptoContextImpl::SerializeEvalAutomorphismKey, id);
    }
    if (serialMode == SerialMode::JSON)
    {
        return SerialDeserial<lbcrypto::SerType::SERJSON, std::ostream, std::ofstream>(
            automorphismKeyLocation, CryptoContextImpl::SerializeEvalAutomorphismKey, id);
    }
    return false;
}
bool DCRTPolySerializeEvalAutomorphismKeyToFile(const std::string& automorphismKeyLocation,
    const CryptoContextDCRTPoly& cryptoContext, const SerialMode serialMode)
{
    if (serialMode == SerialMode::BINARY)
    {
        return SerialDeserial<lbcrypto::SerType::SERBINARY, std::ostream, std::ofstream>(
            automorphismKeyLocation, CryptoContextImpl::SerializeEvalAutomorphismKey,
            cryptoContext.GetRef());
    }
    if (serialMode == SerialMode::JSON)
    {
        return SerialDeserial<lbcrypto::SerType::SERJSON, std::ostream, std::ofstream>(
            automorphismKeyLocation, CryptoContextImpl::SerializeEvalAutomorphismKey,
            cryptoContext.GetRef());
    }
    return false;
}

// EvalMultKey
bool DCRTPolyDeserializeEvalMultKeyFromFile(const std::string& multKeyLocation,
    const SerialMode serialMode)
{
    if (serialMode == SerialMode::BINARY)
    {
        return SerialDeserial<lbcrypto::SerType::SERBINARY, std::istream, std::ifstream>(
            multKeyLocation, CryptoContextImpl::DeserializeEvalMultKey);
    }
    if (serialMode == SerialMode::JSON)
    {
        return SerialDeserial<lbcrypto::SerType::SERJSON, std::istream, std::ifstream>(
            multKeyLocation, CryptoContextImpl::DeserializeEvalMultKey);
    }
    return false;
}
bool SerializeEvalMultKeyDCRTPolyByIdToFile(const std::string& multKeyLocation,
    const SerialMode serialMode, const std::string& id)
{
    if (serialMode == SerialMode::BINARY)
    {
        return SerialDeserial<lbcrypto::SerType::SERBINARY, std::ostream, std::ofstream>(
            multKeyLocation, CryptoContextImpl::SerializeEvalMultKey, id);
    }
    if (serialMode == SerialMode::JSON)
    {
        return SerialDeserial<lbcrypto::SerType::SERJSON, std::ostream, std::ofstream>(
            multKeyLocation, CryptoContextImpl::SerializeEvalMultKey, id);
    }
    return false;
}
bool DCRTPolySerializeEvalMultKeyToFile(const std::string& multKeyLocation,
    const CryptoContextDCRTPoly& cryptoContext, const SerialMode serialMode)
{
    if (serialMode == SerialMode::BINARY)
    {
        return SerialDeserial<lbcrypto::SerType::SERBINARY, std::ostream, std::ofstream>(
            multKeyLocation, CryptoContextImpl::SerializeEvalMultKey, cryptoContext.GetRef());
    }
    if (serialMode == SerialMode::JSON)
    {
        return SerialDeserial<lbcrypto::SerType::SERJSON, std::ostream, std::ofstream>(
            multKeyLocation, CryptoContextImpl::SerializeEvalMultKey, cryptoContext.GetRef());
    }
    return false;
}

// EvalSumKey
bool DCRTPolyDeserializeEvalSumKeyFromFile(const std::string& sumKeyLocation, const SerialMode serialMode)
{
    if (serialMode == SerialMode::BINARY)
    {
        return SerialDeserial<lbcrypto::SerType::SERBINARY, std::istream, std::ifstream>(
            sumKeyLocation, CryptoContextImpl::DeserializeEvalAutomorphismKey);
    }
    if (serialMode == SerialMode::JSON)
    {
        return SerialDeserial<lbcrypto::SerType::SERJSON, std::istream, std::ifstream>(
            sumKeyLocation, CryptoContextImpl::DeserializeEvalAutomorphismKey);
    }
    return false;
}
bool DCRTPolySerializeEvalSumKeyByIdToFile(const std::string& sumKeyLocation,
    const SerialMode serialMode, const std::string& id)
{
    if (serialMode == SerialMode::BINARY)
    {
        return SerialDeserial<lbcrypto::SerType::SERBINARY, std::ostream, std::ofstream>(
            sumKeyLocation, CryptoContextImpl::SerializeEvalSumKey, id);
    }
    if (serialMode == SerialMode::JSON)
    {
        return SerialDeserial<lbcrypto::SerType::SERJSON, std::ostream, std::ofstream>(
            sumKeyLocation, CryptoContextImpl::SerializeEvalSumKey, id);
    }
    return false;
}
bool DCRTPolySerializeEvalSumKeyToFile(const std::string& sumKeyLocation,
    const CryptoContextDCRTPoly& cryptoContext, const SerialMode serialMode)
{
    if (serialMode == SerialMode::BINARY)
    {
        return SerialDeserial<lbcrypto::SerType::SERBINARY, std::ostream, std::ofstream>(
            sumKeyLocation, CryptoContextImpl::SerializeEvalAutomorphismKey,
            cryptoContext.GetRef());
    }
    if (serialMode == SerialMode::JSON)
    {
        return SerialDeserial<lbcrypto::SerType::SERJSON, std::ostream, std::ofstream>(
            sumKeyLocation, CryptoContextImpl::SerializeEvalAutomorphismKey,
            cryptoContext.GetRef());
    }
    return false;
}

// PublicKey
bool DCRTPolyDeserializePublicKeyFromFile(const std::string& publicKeyLocation,
    PublicKeyDCRTPoly& publicKey, const SerialMode serialMode)
{
    return Deserial(publicKeyLocation, publicKey, serialMode);
}
bool DCRTPolySerializePublicKeyToFile(const std::string& publicKeyLocation,
    const PublicKeyDCRTPoly& publicKey, const SerialMode serialMode)
{
    return Serial(publicKeyLocation, publicKey, serialMode);
}

bool DCRTPolyDeserializePublicKeyFromBytes(const std::vector<uint8_t>& bytes,
    PublicKeyDCRTPoly& publicKey)
{
    try {
        std::string byte_string(bytes.begin(), bytes.end());
        std::stringstream stream(byte_string);
        lbcrypto::Serial::Deserialize(publicKey.GetRef(), stream, lbcrypto::SerType::SERBINARY());
        return true; // Success
    } catch (const std::exception& e) {
        return false; // Failure
    }
}

bool DCRTPolySerializePublicKeyToBytes(const PublicKeyDCRTPoly& publicKey,
    std::vector<uint8_t>& out_bytes)
{
    std::ostringstream stream;

    try {

        lbcrypto::Serial::Serialize(publicKey.GetRef(), stream, lbcrypto::SerType::SERBINARY());
        std::string str = stream.str();
        out_bytes.assign(str.begin(), str.end());
        return true;
    } catch (const std::exception& e) {
        return false; // Failure
    }
}

bool DCRTPolyDeserializePrivateKeyFromFile(const std::string& privateKeyLocation,
    PrivateKeyDCRTPoly& privateKey, const SerialMode serialMode)
{
    return Deserial(privateKeyLocation, privateKey, serialMode);
}

bool DCRTPolySerializePrivateKeyToFile(const std::string& privateKeyLocation,
    const PrivateKeyDCRTPoly& privateKey, const SerialMode serialMode)
{
    return Serial(privateKeyLocation, privateKey, serialMode);
}

bool DCRTPolyDeserializePrivateKeyFromBytes(const std::vector<uint8_t>& bytes,
    PrivateKeyDCRTPoly& privateKey)
{
    try {
        std::string byte_string(bytes.begin(), bytes.end());
        std::stringstream stream(byte_string);
        lbcrypto::Serial::Deserialize(privateKey.GetRef(), stream, lbcrypto::SerType::SERBINARY());
        return true; // Success
    } catch (const std::exception& e) {
        return false; // Failure
    }
}

bool DCRTPolySerializePrivateKeyToBytes(const PrivateKeyDCRTPoly& privateKey,
    std::vector<uint8_t>& out_bytes)
{
    std::ostringstream stream;

    try {

        lbcrypto::Serial::Serialize(privateKey.GetRef(), stream, lbcrypto::SerType::SERBINARY());
        std::string str = stream.str();
        out_bytes.assign(str.begin(), str.end());
        return true;
    } catch (const std::exception& e) {
        return false; // Failure
    }
}
} // openfhe
