#include "CryptoParametersBase.h"

#include "openfhe/pke/schemebase/base-cryptoparameters.h"
#include "rust/cxx.h"
#include <string>
#include <sstream>

namespace openfhe
{

CryptoParametersBaseDCRTPoly::CryptoParametersBaseDCRTPoly(
    const std::shared_ptr<CryptoParametersBase>& cryptoParametersBase) noexcept
    : m_cryptoParametersBase(cryptoParametersBase)
{ }

::rust::String CryptoParametersBaseDCRTPolyToString(const CryptoParametersBaseDCRTPoly& cryptoParameters)
{
    if (cryptoParameters.GetCryptoParameters()) {
        std::stringstream stream;
        stream << *(cryptoParameters.GetCryptoParameters());
        return ::rust::String(stream.str());
    }
    return ::rust::String("CryptoParametersBaseDCRTPoly(null)");
}

} // openfhe
