#include "Ciphertext.h"

#include "openfhe/pke/ciphertext.h"

namespace openfhe
{

CiphertextDCRTPoly::CiphertextDCRTPoly(std::shared_ptr<CiphertextImpl>&& ciphertext) noexcept
    : m_ciphertext(std::move(ciphertext))
{ }
const std::shared_ptr<CiphertextImpl>& CiphertextDCRTPoly::GetRef() const noexcept
{
    return m_ciphertext;
}
std::shared_ptr<CiphertextImpl>& CiphertextDCRTPoly::GetRef() noexcept
{
    return m_ciphertext;
}

// Generator functions
std::unique_ptr<CiphertextDCRTPoly> DCRTPolyGenNullCiphertext()
{
    return std::make_unique<CiphertextDCRTPoly>();
}

// Clone function
std::unique_ptr<CiphertextDCRTPoly> DCRTPolyCloneCiphertext(
    const CiphertextDCRTPoly& ciphertext)
{
    return std::make_unique<CiphertextDCRTPoly>(ciphertext.GetRef() -> Clone());
}

// Equality function
bool AreCiphertextsEqual(const CiphertextDCRTPoly& a, const CiphertextDCRTPoly& b)
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
