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
std::unique_ptr<CiphertextDCRTPoly> DCRTPolyCloneCiphertext(
    const CiphertextDCRTPoly& ciphertext)
{
    std::lock_guard<std::mutex> lock(ciphertext_clone_mutex);
    
    // Check if the ciphertext has a valid internal object
    const auto& ref = ciphertext.GetRef();
    if (!ref) {
        // If the source ciphertext is null, return a null ciphertext
        return std::make_unique<CiphertextDCRTPoly>();
    }
    
    // Clone the actual ciphertext
    return std::make_unique<CiphertextDCRTPoly>(ref->Clone());
}

// Equality function
bool AreCiphertextsEqual(const CiphertextDCRTPoly& a, const CiphertextDCRTPoly& b)
{
    return AreObjectsEqual(a, b);
}

} // openfhe
