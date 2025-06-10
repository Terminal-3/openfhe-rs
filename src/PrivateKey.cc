#include "PrivateKey.h"

#include "openfhe/pke/key/privatekey.h"

namespace openfhe
{

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
    // return std::make_unique<PublicKeyDCRTPoly>(publicKey.GetRef() -> Clone());
    // that does not work because the clone function is not implemented
    // so we need to do it manually
    auto new_private_key = std::make_shared<PrivateKeyImpl>();
    // copy the public key
    *new_private_key = *privateKey.GetRef();
    // return the new public key
    return std::make_unique<PrivateKeyDCRTPoly>(new_private_key);
}

// Equality function
bool ArePrivateKeysEqual(const PrivateKeyDCRTPoly& a, const PrivateKeyDCRTPoly& b)
{
    // Quick check: if they're the same object, they're definitely equal
    if (a.GetRef() == b.GetRef()) {
        return true;
    }
    
    // If either key is null/empty, they can only be equal if both are null
    if (!a.GetRef() || !b.GetRef()) {
        return !a.GetRef() && !b.GetRef();
    }
    
    // Use the underlying PublicKeyImpl's operator== which compares actual key content
    return *a.GetRef() == *b.GetRef();
}

} // openfhe
