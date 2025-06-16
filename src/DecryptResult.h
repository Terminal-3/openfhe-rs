#pragma once

#include "openfhe/pke/schemebase/decrypt-result.h"

namespace openfhe
{

class DecryptResult final
{
	lbcrypto::DecryptResult m_decryptResult;
public:
    DecryptResult(lbcrypto::DecryptResult&& decryptResult) noexcept;
    DecryptResult(const DecryptResult&) = delete;
    DecryptResult(DecryptResult&&) = delete;
    DecryptResult& operator=(const DecryptResult&) = delete;
    DecryptResult& operator=(DecryptResult&&) = delete;

    // Check if decryption was successful
    bool DecryptResultIsValid() const noexcept { return m_decryptResult.isValid; }

    // Get the length of the decrypted message
    uint32_t DecryptResultMessageLength() const noexcept { return m_decryptResult.messageLength; }

};

} // openfhe
