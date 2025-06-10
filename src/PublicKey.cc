#include "PublicKey.h"

#include "openfhe/pke/key/publickey.h"

namespace openfhe
{

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
    // return std::make_unique<PublicKeyDCRTPoly>(publicKey.GetRef() -> Clone());
    // that does not work because the clone function is not implemented
    // so we need to do it manually
    auto new_public_key = std::make_shared<PublicKeyImpl>();
    // copy the public key
    *new_public_key = *publicKey.GetRef();
    // return the new public key
    return std::make_unique<PublicKeyDCRTPoly>(new_public_key);
}

// Equality function
bool ArePublicKeysEqual(const PublicKeyDCRTPoly& a, const PublicKeyDCRTPoly& b)
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
