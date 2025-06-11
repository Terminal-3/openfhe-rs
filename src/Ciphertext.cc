#include "Ciphertext.h"
#include "EqualityUtils.h"

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
    return AreObjectsEqual(a, b);
}

} // openfhe
