#pragma once

#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/TestCollection.h>

#include <cstddef>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>

namespace tests_libOTe::logvole_test
{
    template<typename T, typename = void>
    struct is_streamable : std::false_type
    {};

    template<typename T>
    struct is_streamable<T, std::void_t<decltype(std::declval<std::ostream&>() << std::declval<const T&>())>>
        : std::true_type
    {};

    template<typename T>
    std::string value_to_string(const T& value)
    {
        if constexpr (is_streamable<T>::value)
        {
            std::ostringstream out;
            out << value;
            return out.str();
        }
        else
        {
            return "<unprintable>";
        }
    }

    class assertion
    {
    public:
        assertion(bool passed, const char* macro, const char* expr, const char* file, int line)
            : mPassed(passed)
        {
            if (!mPassed)
            {
                mMessage << file << ":" << line << ": " << macro << " failed: " << expr;
            }
        }

        assertion(const assertion&) = delete;
        assertion& operator=(const assertion&) = delete;

        assertion(assertion&& other) noexcept
            : mPassed(other.mPassed),
              mMessage(std::move(other.mMessage))
        {
            other.mPassed = true;
        }

        ~assertion() noexcept(false)
        {
            if (!mPassed)
            {
                throw osuCrypto::UnitTestFail(mMessage.str());
            }
        }

        template<typename T>
        assertion& operator<<(const T& value)
        {
            if (!mPassed)
            {
                mMessage << value;
            }
            return *this;
        }

    private:
        bool mPassed;
        std::ostringstream mMessage;
    };

    class skip
    {
    public:
        skip(const char* file, int line)
        {
            mMessage << file << ":" << line << ": skipped";
        }

        skip(const skip&) = delete;
        skip& operator=(const skip&) = delete;

        skip(skip&& other) noexcept
            : mMessage(std::move(other.mMessage)),
              mActive(other.mActive)
        {
            other.mActive = false;
        }

        ~skip() noexcept(false)
        {
            if (mActive)
            {
                throw osuCrypto::UnitTestSkipped(mMessage.str());
            }
        }

        template<typename T>
        skip& operator<<(const T& value)
        {
            mMessage << value;
            return *this;
        }

    private:
        std::ostringstream mMessage;
        bool mActive = true;
    };

    inline assertion check_true(bool value, const char* macro, const char* expr, const char* file, int line)
    {
        return assertion(value, macro, expr, file, line);
    }

    template<typename L, typename R>
    assertion check_eq(const L& lhs, const R& rhs, const char* macro, const char* expr, const char* file, int line)
    {
        auto result = assertion(lhs == rhs, macro, expr, file, line);
        if (!(lhs == rhs))
        {
            result << " (" << value_to_string(lhs) << " vs " << value_to_string(rhs) << ")";
        }
        return result;
    }

    template<typename L, typename R>
    assertion check_gt(const L& lhs, const R& rhs, const char* macro, const char* expr, const char* file, int line)
    {
        auto result = assertion(lhs > rhs, macro, expr, file, line);
        if (!(lhs > rhs))
        {
            result << " (" << value_to_string(lhs) << " vs " << value_to_string(rhs) << ")";
        }
        return result;
    }

    template<typename L, typename R>
    assertion check_lt(const L& lhs, const R& rhs, const char* macro, const char* expr, const char* file, int line)
    {
        auto result = assertion(lhs < rhs, macro, expr, file, line);
        if (!(lhs < rhs))
        {
            result << " (" << value_to_string(lhs) << " vs " << value_to_string(rhs) << ")";
        }
        return result;
    }
} // namespace tests_libOTe::logvole_test

#define TEST(suite, name) void LogVole_##suite##_##name(const oc::CLP&)

#define ASSERT_TRUE(expr) \
    ::tests_libOTe::logvole_test::check_true(static_cast<bool>(expr), "ASSERT_TRUE", #expr, __FILE__, __LINE__)
#define EXPECT_TRUE(expr) \
    ::tests_libOTe::logvole_test::check_true(static_cast<bool>(expr), "EXPECT_TRUE", #expr, __FILE__, __LINE__)
#define ASSERT_FALSE(expr) \
    ::tests_libOTe::logvole_test::check_true(!static_cast<bool>(expr), "ASSERT_FALSE", #expr, __FILE__, __LINE__)
#define EXPECT_FALSE(expr) \
    ::tests_libOTe::logvole_test::check_true(!static_cast<bool>(expr), "EXPECT_FALSE", #expr, __FILE__, __LINE__)
#define ASSERT_EQ(lhs, rhs) \
    ::tests_libOTe::logvole_test::check_eq((lhs), (rhs), "ASSERT_EQ", #lhs " == " #rhs, __FILE__, __LINE__)
#define EXPECT_EQ(lhs, rhs) \
    ::tests_libOTe::logvole_test::check_eq((lhs), (rhs), "EXPECT_EQ", #lhs " == " #rhs, __FILE__, __LINE__)
#define ASSERT_GT(lhs, rhs) \
    ::tests_libOTe::logvole_test::check_gt((lhs), (rhs), "ASSERT_GT", #lhs " > " #rhs, __FILE__, __LINE__)
#define EXPECT_GT(lhs, rhs) \
    ::tests_libOTe::logvole_test::check_gt((lhs), (rhs), "EXPECT_GT", #lhs " > " #rhs, __FILE__, __LINE__)
#define ASSERT_LT(lhs, rhs) \
    ::tests_libOTe::logvole_test::check_lt((lhs), (rhs), "ASSERT_LT", #lhs " < " #rhs, __FILE__, __LINE__)
#define EXPECT_LT(lhs, rhs) \
    ::tests_libOTe::logvole_test::check_lt((lhs), (rhs), "EXPECT_LT", #lhs " < " #rhs, __FILE__, __LINE__)

#define GTEST_SKIP() ::tests_libOTe::logvole_test::skip(__FILE__, __LINE__)
