#pragma once

#include <cryptoTools/Common/TestCollection.h>
#include "libOTe/Vole/LogVole/LogVole.h"

#include <cstdlib>
#include <sstream>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>

namespace tests_libOTe::logvole_test
{
    using ExecutionPtr = osuCrypto::LogVole::ExecutionContextPtr;

    template<class T>
    void bindExecution(T& value, const ExecutionPtr& execution)
    {
        execution->mCacheGpuOptions = false;
        if constexpr (requires { value.execution(); }) value.execution().mCacheGpuOptions = false;
        if constexpr (requires { value.mUseGpu = true; }) value.mUseGpu = execution->mUseGpu;
        if constexpr (requires { value.mExecutionContext = execution; }) value.mExecutionContext = execution;
        else if constexpr (requires { value.mParams; }) bindExecution(value.mParams, execution);
        else if constexpr (requires { value.mLogVole; }) bindExecution(value.mLogVole, execution);
        else if constexpr (requires { value.mShrinkExpand; }) bindExecution(value.mShrinkExpand, execution);
        else if constexpr (requires { value.mRing; }) bindExecution(value.mRing, execution);
    }

    template<class T>
    T withExecution(T value, const ExecutionPtr& execution)
    {
        bindExecution(value, execution);
        return value;
    }

    struct ScopedGpuEnabled
    {
        ExecutionPtr mExecution;
        bool mPrevious;
        ScopedGpuEnabled(ExecutionPtr execution, bool enabled)
            : mExecution(std::move(execution)), mPrevious(mExecution->mUseGpu)
        { mExecution->mUseGpu = enabled; }
        ~ScopedGpuEnabled() { mExecution->mUseGpu = mPrevious; }
    };

    struct ScopedCpuBenchmark
    {
        ExecutionPtr mExecution;
        osuCrypto::LogVole::CpuBenchmarkContext* mPrevious;
        ScopedCpuBenchmark(ExecutionPtr execution, osuCrypto::LogVole::CpuBenchmarkContext* context)
            : mExecution(std::move(execution)), mPrevious(mExecution->mCpuBenchmark)
        { mExecution->mCpuBenchmark = context; }
        ~ScopedCpuBenchmark() { mExecution->mCpuBenchmark = mPrevious; }
    };

    struct ScopedProtocolCacheScope
    {
        ExecutionPtr mExecution;
        osuCrypto::LogVole::ProtocolCacheScope mPrevious;
        ScopedProtocolCacheScope(ExecutionPtr execution, osuCrypto::LogVole::ProtocolCacheRole role,
            osuCrypto::u64 runId)
            : mExecution(std::move(execution)), mPrevious(mExecution->mScope)
        { mExecution->mScope = {runId, role}; }
        ~ScopedProtocolCacheScope() { mExecution->mScope = mPrevious; }
    };

    inline osuCrypto::u64 allocateRunId(const ExecutionPtr& execution)
    {
        struct Counter { std::atomic<osuCrypto::u64> mNext{1}; };
        return execution->resources<Counter>().mNext.fetch_add(1);
    }

    inline bool makeRingNttContext(const ExecutionPtr& execution,
        osuCrypto::LogVole::RingParams params, osuCrypto::LogVole::RingNttContext& out)
    {
        params.mExecutionContext = execution;
        return osuCrypto::LogVole::makeRingNttContext(params, out);
    }
    inline bool makeGpuRingNttContext(const ExecutionPtr& execution,
        osuCrypto::LogVole::RingParams params, osuCrypto::LogVole::RingNttContext& out)
    {
        params.mExecutionContext = execution;
        return osuCrypto::LogVole::makeGpuRingNttContext(params, out);
    }
    inline bool makeZpCrtContext(const ExecutionPtr& execution,
        osuCrypto::LogVole::RingParams params, osuCrypto::u32 bits,
        osuCrypto::LogVole::ZpCrtContext& out)
    {
        params.mExecutionContext = execution;
        return osuCrypto::LogVole::makeZpCrtContext(params, bits, out);
    }

    inline int setEnvironment(const char* name, const char* value, int overwrite)
    {
#if defined(_WIN32)
        if (!overwrite && std::getenv(name)) return 0;
        return _putenv_s(name, value);
#else
        return ::setenv(name, value, overwrite);
#endif
    }

    inline int unsetEnvironment(const char* name)
    {
#if defined(_WIN32)
        return _putenv_s(name, "");
#else
        return ::unsetenv(name);
#endif
    }

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
        assertion(bool passed, const char* check_name, const char* expr, const char* file, int line)
            : mPassed(passed)
        {
            if (!mPassed)
            {
                mMessage << file << ":" << line << ": " << check_name << " failed: " << expr;
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

    class thread_join_guard
    {
    public:
        explicit thread_join_guard(std::thread& thread)
            : mThread(thread)
        {}

        thread_join_guard(const thread_join_guard&) = delete;
        thread_join_guard& operator=(const thread_join_guard&) = delete;

        ~thread_join_guard()
        {
            join();
        }

        void join()
        {
            if (mThread.joinable())
            {
                mThread.join();
            }
        }

    private:
        std::thread& mThread;
    };

    inline assertion require_true(bool value, const char* expr, const char* file, int line)
    {
        return assertion(value, "require_true", expr, file, line);
    }

    inline assertion expect_true(bool value, const char* expr, const char* file, int line)
    {
        return assertion(value, "expect_true", expr, file, line);
    }

    inline assertion require_false(bool value, const char* expr, const char* file, int line)
    {
        return assertion(!value, "require_false", expr, file, line);
    }

    inline assertion expect_false(bool value, const char* expr, const char* file, int line)
    {
        return assertion(!value, "expect_false", expr, file, line);
    }

    template<typename L, typename R>
    assertion require_eq(const L& lhs, const R& rhs, const char* expr, const char* file, int line)
    {
        auto result = assertion(lhs == rhs, "require_eq", expr, file, line);
        if (!(lhs == rhs))
        {
            result << " (" << value_to_string(lhs) << " vs " << value_to_string(rhs) << ")";
        }
        return result;
    }

    template<typename L, typename R>
    assertion expect_eq(const L& lhs, const R& rhs, const char* expr, const char* file, int line)
    {
        auto result = assertion(lhs == rhs, "expect_eq", expr, file, line);
        if (!(lhs == rhs))
        {
            result << " (" << value_to_string(lhs) << " vs " << value_to_string(rhs) << ")";
        }
        return result;
    }

    template<typename L, typename R>
    assertion require_gt(const L& lhs, const R& rhs, const char* expr, const char* file, int line)
    {
        auto result = assertion(lhs > rhs, "require_gt", expr, file, line);
        if (!(lhs > rhs))
        {
            result << " (" << value_to_string(lhs) << " vs " << value_to_string(rhs) << ")";
        }
        return result;
    }

    template<typename L, typename R>
    assertion expect_gt(const L& lhs, const R& rhs, const char* expr, const char* file, int line)
    {
        auto result = assertion(lhs > rhs, "expect_gt", expr, file, line);
        if (!(lhs > rhs))
        {
            result << " (" << value_to_string(lhs) << " vs " << value_to_string(rhs) << ")";
        }
        return result;
    }

    template<typename L, typename R>
    assertion require_lt(const L& lhs, const R& rhs, const char* expr, const char* file, int line)
    {
        auto result = assertion(lhs < rhs, "require_lt", expr, file, line);
        if (!(lhs < rhs))
        {
            result << " (" << value_to_string(lhs) << " vs " << value_to_string(rhs) << ")";
        }
        return result;
    }

    template<typename L, typename R>
    assertion expect_lt(const L& lhs, const R& rhs, const char* expr, const char* file, int line)
    {
        auto result = assertion(lhs < rhs, "expect_lt", expr, file, line);
        if (!(lhs < rhs))
        {
            result << " (" << value_to_string(lhs) << " vs " << value_to_string(rhs) << ")";
        }
        return result;
    }
} // namespace tests_libOTe::logvole_test

#define LOGVOLE_REQUIRE_TRUE(expr) \
    ::tests_libOTe::logvole_test::require_true(static_cast<bool>(expr), #expr, __FILE__, __LINE__)
#define LOGVOLE_EXPECT_TRUE(expr) \
    ::tests_libOTe::logvole_test::expect_true(static_cast<bool>(expr), #expr, __FILE__, __LINE__)
#define LOGVOLE_REQUIRE_FALSE(expr) \
    ::tests_libOTe::logvole_test::require_false(static_cast<bool>(expr), #expr, __FILE__, __LINE__)
#define LOGVOLE_EXPECT_FALSE(expr) \
    ::tests_libOTe::logvole_test::expect_false(static_cast<bool>(expr), #expr, __FILE__, __LINE__)
#define LOGVOLE_REQUIRE_EQ(lhs, rhs) \
    ::tests_libOTe::logvole_test::require_eq((lhs), (rhs), #lhs " == " #rhs, __FILE__, __LINE__)
#define LOGVOLE_EXPECT_EQ(lhs, rhs) \
    ::tests_libOTe::logvole_test::expect_eq((lhs), (rhs), #lhs " == " #rhs, __FILE__, __LINE__)
#define LOGVOLE_REQUIRE_GT(lhs, rhs) \
    ::tests_libOTe::logvole_test::require_gt((lhs), (rhs), #lhs " > " #rhs, __FILE__, __LINE__)
#define LOGVOLE_EXPECT_GT(lhs, rhs) \
    ::tests_libOTe::logvole_test::expect_gt((lhs), (rhs), #lhs " > " #rhs, __FILE__, __LINE__)
#define LOGVOLE_REQUIRE_LT(lhs, rhs) \
    ::tests_libOTe::logvole_test::require_lt((lhs), (rhs), #lhs " < " #rhs, __FILE__, __LINE__)
#define LOGVOLE_EXPECT_LT(lhs, rhs) \
    ::tests_libOTe::logvole_test::expect_lt((lhs), (rhs), #lhs " < " #rhs, __FILE__, __LINE__)
#define LOGVOLE_SKIP() ::tests_libOTe::logvole_test::skip(__FILE__, __LINE__)
