#include "PublicKey.h"
#include "EqualityUtils.h"

#include "openfhe/pke/key/publickey.h"
#include <memory>
#include <mutex>

namespace openfhe
{
    static std::mutex openfhe_mutex;

PublicKeyDCRTPoly::PublicKeyDCRTPoly(const std::shared_ptr<PublicKeyImpl>& publicKey) noexcept
    : m_publicKey(publicKey)
{ }

const std::shared_ptr<PublicKeyImpl>& PublicKeyDCRTPoly::GetRef() const noexcept
{
    return m_publicKey;
}

std::shared_ptr<PublicKeyImpl>& PublicKeyDCRTPoly::GetRef() noexcept
{
    return m_publicKey;
}

// Generator functions
std::unique_ptr<PublicKeyDCRTPoly> DCRTPolyGenNullPublicKey()
{
    return std::make_unique<PublicKeyDCRTPoly>();
}

// Clone function
std::unique_ptr<PublicKeyDCRTPoly> DCRTPolyClonePublicKey(
    const PublicKeyDCRTPoly& publicKey)
{
    // Thread-safe clone operation
    std::lock_guard<std::mutex> lock(openfhe_mutex);
    
    if (!publicKey.GetRef()) {
        return std::make_unique<PublicKeyDCRTPoly>();
    }

    auto new_public_key = std::make_shared<PublicKeyImpl>();
    // copy the public key
    *new_public_key = *publicKey.GetRef();
    // return the new public key
    return std::make_unique<PublicKeyDCRTPoly>(new_public_key);
}

// Equality function using the template
bool ArePublicKeysEqual(const PublicKeyDCRTPoly& a, const PublicKeyDCRTPoly& b)
{
    return AreObjectsEqual(a, b);
}

} // openfhe
