#pragma once

#include "openfhe/core/lattice/hal/lat-backend.h"
#include "openfhe/pke/ciphertext-fwd.h"

namespace openfhe
{

using CiphertextImpl = lbcrypto::CiphertextImpl<lbcrypto::DCRTPoly>;

class CiphertextDCRTPoly final
{
    std::shared_ptr<CiphertextImpl> m_ciphertext;
public:
    CiphertextDCRTPoly() = default;
    CiphertextDCRTPoly(std::shared_ptr<CiphertextImpl>&& ciphertext) noexcept;
    CiphertextDCRTPoly(const CiphertextDCRTPoly&) = delete;
    CiphertextDCRTPoly(CiphertextDCRTPoly&&) = delete;
    CiphertextDCRTPoly& operator=(const CiphertextDCRTPoly&) = delete;
    CiphertextDCRTPoly& operator=(CiphertextDCRTPoly&&) = delete;

    [[nodiscard]] const std::shared_ptr<CiphertextImpl>& GetRef() const noexcept;
    [[nodiscard]] std::shared_ptr<CiphertextImpl>& GetRef() noexcept;
};

// Generator functions
[[nodiscard]] std::unique_ptr<CiphertextDCRTPoly> DCRTPolyGenNullCiphertext();


// Clone function
[[nodiscard]] std::unique_ptr<CiphertextDCRTPoly> DCRTPolyCloneCiphertext(
    const CiphertextDCRTPoly& ciphertext);

// Equality function
[[nodiscard]] bool AreCiphertextsEqual(const CiphertextDCRTPoly& a,
    const CiphertextDCRTPoly& b);
} // openfhe
