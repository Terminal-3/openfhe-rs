#include "Ciphertext.h"
#include "EqualityUtils.h"

#include "openfhe/pke/ciphertext.h"


namespace openfhe
{

std::mutex ciphertext_clone_mutex;

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
// need to add mutex lock here
std::unique_ptr<CiphertextDCRTPoly> DCRTPolyCloneCiphertext(
    const CiphertextDCRTPoly& ciphertext)
{
    // need to add mutex lock here
    std::lock_guard<std::mutex> lock(ciphertext_clone_mutex);
    return std::make_unique<CiphertextDCRTPoly>(ciphertext.GetRef() -> Clone());
}

// Equality function
bool AreCiphertextsEqual(const CiphertextDCRTPoly& a, const CiphertextDCRTPoly& b)
{
    return AreObjectsEqual(a, b);
}

} // openfhe
