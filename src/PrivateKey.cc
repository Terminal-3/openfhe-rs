#include "PrivateKey.h"
#include "EqualityUtils.h"

#include "openfhe/pke/key/privatekey.h"

namespace openfhe
{
    static std::mutex openfhe_mutex;

PrivateKeyDCRTPoly::PrivateKeyDCRTPoly(const std::shared_ptr<PrivateKeyImpl>& privateKey) noexcept
    : m_privateKey(privateKey)
{ }

const std::shared_ptr<PrivateKeyImpl>& PrivateKeyDCRTPoly::GetRef() const noexcept
{
    return m_privateKey;
}

std::shared_ptr<PrivateKeyImpl>& PrivateKeyDCRTPoly::GetRef() noexcept
{
    return m_privateKey;
}

std::unique_ptr<PrivateKeyDCRTPoly> DCRTPolyGenNullPrivateKey()
{
    return std::make_unique<PrivateKeyDCRTPoly>();
}

std::unique_ptr<PrivateKeyDCRTPoly> DCRTPolyClonePrivateKey(
    const PrivateKeyDCRTPoly& privateKey)
{
    // Thread-safe clone operation
    std::lock_guard<std::mutex> lock(openfhe_mutex);
    
    if (!privateKey.GetRef()) {
        return std::make_unique<PrivateKeyDCRTPoly>();
    }
    
    auto new_private_key = std::make_shared<PrivateKeyImpl>();
    *new_private_key = *privateKey.GetRef();  // Now protected by mutex
    return std::make_unique<PrivateKeyDCRTPoly>(new_private_key);
}

// Equality function using the template (with mutex for thread safety)
bool ArePrivateKeysEqual(const PrivateKeyDCRTPoly& a, const PrivateKeyDCRTPoly& b)
{
    return AreObjectsEqual(a, b);  // Use mutex for private key comparisons
}

} // openfhe
