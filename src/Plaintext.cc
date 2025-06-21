#include "Plaintext.h"
#include "EqualityUtils.h"

#include "openfhe/pke/encoding/plaintext.h"

#include "openfhe/src/lib.rs.h"
#include <memory>
#include <mutex>

namespace openfhe
{

std::mutex plaintext_clone_mutex;

Plaintext::Plaintext(std::shared_ptr<PlaintextImpl>&& plaintext) noexcept
    : m_plaintext(std::move(plaintext))
{ }
void Plaintext::SetLength(const size_t newSize) const
{
    m_plaintext->SetLength(newSize);
}
void Plaintext::SetLevel(const size_t l) const noexcept
{
    m_plaintext->SetLevel(l);
}
bool Plaintext::IsEncoded() const noexcept
{
    return m_plaintext->IsEncoded();
}
int64_t Plaintext::HighBound() const noexcept
{
    return m_plaintext->HighBound();
}
int64_t Plaintext::LowBound() const noexcept
{
    return m_plaintext->LowBound();
}
double Plaintext::GetLogPrecision() const
{
    return m_plaintext->GetLogPrecision();
}
rust::String Plaintext::GetString() const
{
    std::stringstream stream;
    stream << *m_plaintext;
    return rust::String(stream.str());
}
size_t Plaintext::GetLength() const noexcept
{
    return m_plaintext->GetLength();
}
size_t Plaintext::GetLevel() const noexcept
{
    return m_plaintext->GetLevel();
}
double Plaintext::GetLogError() const
{
    return m_plaintext->GetLogError();
}
size_t Plaintext::GetNoiseScaleDeg() const noexcept
{
    return m_plaintext->GetNoiseScaleDeg();
}
double Plaintext::GetScalingFactor() const noexcept
{
    return m_plaintext->GetScalingFactor();
}
SCHEME Plaintext::GetSchemeID() const noexcept
{
    return m_plaintext->GetSchemeID();
}
uint32_t Plaintext::GetSlots() const noexcept
{
    return m_plaintext->GetSlots();
}
bool Plaintext::Encode() const
{
    return m_plaintext->Encode();
}
bool Plaintext::Decode() const
{
    return m_plaintext->Decode();
}
void Plaintext::SetFormat(const Format fmt) const
{
    m_plaintext->SetFormat(fmt);
}
void Plaintext::SetIntVectorValue(const std::vector<int64_t>& val) const
{
    m_plaintext->SetIntVectorValue(val);
}
void Plaintext::SetNoiseScaleDeg(const size_t nsd) const noexcept
{
    m_plaintext->SetNoiseScaleDeg(nsd);
}
void Plaintext::SetScalingFactor(const double sf) const noexcept
{
    m_plaintext->SetScalingFactor(sf);
}
void Plaintext::SetSlots(const uint32_t s) const noexcept
{
    m_plaintext->SetSlots(s);
}
void Plaintext::SetStringValue(const std::string& value) const
{
    m_plaintext->SetStringValue(value);
}
std::unique_ptr<std::vector<ComplexPair>> Plaintext::GetCopyOfCKKSPackedValue() const
{
    const std::vector<std::complex<double>>& v = m_plaintext->GetCKKSPackedValue();
    std::vector<ComplexPair> result;
    result.reserve(v.size());
    for (const std::complex<double>& elem : v)
    {
        result.push_back(ComplexPair{elem.real(), elem.imag()});
    }
    return std::make_unique<std::vector<ComplexPair>>(std::move(result));
}
const std::vector<int64_t>& Plaintext::GetPackedValue() const
{
    return m_plaintext->GetPackedValue();
}
std::unique_ptr<std::vector<double>>Plaintext::GetRealPackedValue() const
{
    return std::make_unique<std::vector<double>>(m_plaintext->GetRealPackedValue());
}
const std::vector<int64_t>& Plaintext::GetCoefPackedValue() const
{
    return m_plaintext->GetCoefPackedValue();
}
const std::string& Plaintext::GetStringValue() const
{
    return m_plaintext->GetStringValue();
}
const std::shared_ptr<PlaintextImpl>& Plaintext::GetRef() const noexcept
{
    return m_plaintext;
}
std::shared_ptr<PlaintextImpl>& Plaintext::GetRef() noexcept
{
    return m_plaintext;
}

// Generator functions
std::unique_ptr<Plaintext> GenNullPlainText()
{
    return std::make_unique<Plaintext>();
}

// Equality function
bool ArePlaintextsEqual(const Plaintext& a, const Plaintext& b)
{
    return AreObjectsEqual(a, b);
}


} // openfhe
