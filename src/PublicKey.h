#pragma once

#include "openfhe/core/lattice/hal/lat-backend.h"
#include "openfhe/pke/key/publickey-fwd.h"

namespace openfhe
{

using PublicKeyImpl = lbcrypto::PublicKeyImpl<lbcrypto::DCRTPoly>;

class PublicKeyDCRTPoly final
{
    std::shared_ptr<PublicKeyImpl> m_publicKey;
public:
    PublicKeyDCRTPoly() = default;
    PublicKeyDCRTPoly(const std::shared_ptr<PublicKeyImpl>& publicKey) noexcept;
    PublicKeyDCRTPoly(const PublicKeyDCRTPoly&) = delete;
    PublicKeyDCRTPoly(PublicKeyDCRTPoly&&) = delete;
    PublicKeyDCRTPoly& operator=(const PublicKeyDCRTPoly&) = delete;
    PublicKeyDCRTPoly& operator=(PublicKeyDCRTPoly&&) = delete;

    [[nodiscard]] const std::shared_ptr<PublicKeyImpl>& GetRef() const noexcept;
    [[nodiscard]] std::shared_ptr<PublicKeyImpl>& GetRef() noexcept;
};

// Generator functions
[[nodiscard]] std::unique_ptr<PublicKeyDCRTPoly> DCRTPolyGenNullPublicKey();

// Clone function
[[nodiscard]] std::unique_ptr<PublicKeyDCRTPoly> DCRTPolyClonePublicKey(
    const PublicKeyDCRTPoly& publicKey);

// Equality function
[[nodiscard]] bool ArePublicKeysEqual(const PublicKeyDCRTPoly& a,
    const PublicKeyDCRTPoly& b);

} // openfhe
