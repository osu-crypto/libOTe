#pragma once

#include "libOTe_Tests/LogVole_TestUtil.h"

#define TEST(suite, name) void LogVole_##suite##_##name(const oc::CLP&)

#define ASSERT_TRUE(expr) LOGVOLE_REQUIRE_TRUE(expr)
#define EXPECT_TRUE(expr) LOGVOLE_EXPECT_TRUE(expr)
#define ASSERT_FALSE(expr) LOGVOLE_REQUIRE_FALSE(expr)
#define EXPECT_FALSE(expr) LOGVOLE_EXPECT_FALSE(expr)
#define ASSERT_EQ(lhs, rhs) LOGVOLE_REQUIRE_EQ(lhs, rhs)
#define EXPECT_EQ(lhs, rhs) LOGVOLE_EXPECT_EQ(lhs, rhs)
#define ASSERT_GT(lhs, rhs) LOGVOLE_EXPECT_GT(lhs, rhs)
#define EXPECT_GT(lhs, rhs) LOGVOLE_EXPECT_GT(lhs, rhs)
#define ASSERT_LT(lhs, rhs) LOGVOLE_EXPECT_LT(lhs, rhs)
#define EXPECT_LT(lhs, rhs) LOGVOLE_EXPECT_LT(lhs, rhs)

#define GTEST_SKIP() ::tests_libOTe::logvole_test::skip(__FILE__, __LINE__)
