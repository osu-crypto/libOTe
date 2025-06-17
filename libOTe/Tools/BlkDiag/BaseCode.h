#pragma once
#include <vector>
#include "cryptoTools/Common/Defines.h"

namespace osuCrypto
{

    template <typename T>
    class BaseCode {
    public:

        u64 mK = 0;
        u64 mN = 0;

		BaseCode() = default;
		BaseCode(u64 k, u64 n) : mK(k), mN(n) {}
		BaseCode(const BaseCode&) = default;
		BaseCode(BaseCode&&) = default;
		BaseCode& operator=(const BaseCode&) = default;
		BaseCode& operator=(BaseCode&&) = default;


        virtual ~BaseCode() = default;

        // if inplace, input to invoke will be ignored and must be size 0
		// the input data will be in output.
        virtual bool inplace() const = 0;


        virtual void invoke(span<const T> input, span<T> output) = 0;

    };

}