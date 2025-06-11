#pragma once

#include <memory>
#include <mutex>

namespace openfhe {


/**
 * @brief Generic equality comparison template for OpenFHE wrapper classes
 * 
 * This template function provides a standardized way to compare equality between
 * wrapper objects that follow the pattern of having a GetRef() method returning
 * a shared_ptr to the underlying implementation.
 * 
 * @tparam WrapperType The wrapper class type (e.g., PublicKeyDCRTPoly, PrivateKeyDCRTPoly)
 * @param a First object to compare
 * @param b Second object to compare
 * @param use_mutex Whether to use mutex for thread-safe comparison (default: false)
 * @return true if objects are equal, false otherwise
 */
template<typename WrapperType>
bool AreObjectsEqual(const WrapperType& a, const WrapperType& b)
{
    // Optional thread-safe operation
    // if (use_mutex) {
    //     std::lock_guard<std::mutex> lock(openfhe_mutex);
    //     return AreObjectsEqualImpl(a, b);
    // }
    return AreObjectsEqualImpl(a, b);
}

/**
 * @brief Internal implementation of equality comparison
 * 
 * @tparam WrapperType The wrapper class type
 * @param a First object to compare
 * @param b Second object to compare
 * @return true if objects are equal, false otherwise
 */
template<typename WrapperType>
bool AreObjectsEqualImpl(const WrapperType& a, const WrapperType& b)
{
    // Quick check: if they're the same object, they're definitely equal
    if (a.GetRef() == b.GetRef()) {
        return true;
    }
    
    // If either object is null/empty, they can only be equal if both are null
    if (!a.GetRef() || !b.GetRef()) {
        return !a.GetRef() && !b.GetRef();
    }
    
    // Use the underlying implementation's operator== which compares actual content
    return *a.GetRef() == *b.GetRef();
}

} // namespace openfhe 