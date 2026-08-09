#pragma once

#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"
#include "libOTe/Dpf/DpfMult.h"

#include <algorithm>
#include <bit>
#include <array>
#include <limits>
#include <stdexcept>
#include <utility>
#include <vector>

namespace osuCrypto
{
	/// Exact t-wise independent Waterfall hash over GF(2^ell).
	///
	/// Secret field multiplications use a generated bilinear circuit. At ell=20,
	/// a GF(16)^5 tower construction uses 81 shared bit products while public
	/// multiplication remains a single carry-less multiply in polynomial basis.
	/// Powers are prepared once and reused across arbitrarily many public seeds.
	class WaterfallHash
	{
		struct Leaf
		{
			u32 mLeftMask = 0;
			u32 mRightMask = 0;
		};

		using Expression = std::vector<std::vector<u32>>;

		u64 mPartyIdx = 0;
		u64 mNumRows = 0;
		u64 mDegree = 0;
		u64 mFieldBits = 0;
		u64 mOddPowerCount = 0;
		u64 mModulus = 0;
		std::array<std::array<u32, 256>, 4> mReductionTable{};
		std::vector<Leaf> mLeaves;
		Expression mRawProduct;

		static u8 gf16Multiply(u8 left, u8 right)
		{
			u8 raw = 0;
			for (u64 bit = 0; bit < 4; ++bit)
				raw ^= ((right >> bit) & 1) * (left << bit);
			for (u64 degree = 6; degree >= 4; --degree)
				if ((raw >> degree) & 1)
					raw ^= static_cast<u8>(0x13 << (degree - 4));
			return raw & 0xf;
		}

		static u8 gf16Power(u8 value, u64 exponent)
		{
			u8 result = 1;
			while (exponent)
			{
				if (exponent & 1)
					result = gf16Multiply(result, value);
				value = gf16Multiply(value, value);
				exponent >>= 1;
			}
			return result;
		}

		static u32 towerMultiplyRaw(u32 left, u32 right)
		{
			std::array<u8, 9> product{};
			for (u64 i = 0; i < 5; ++i)
				for (u64 j = 0; j < 5; ++j)
					product[i + j] ^= gf16Multiply(
						(left >> (4 * i)) & 0xf,
						(right >> (4 * j)) & 0xf);
			// The extension polynomial is Y^5 + Y^2 + 1.
			for (u64 degree = 8; degree >= 5; --degree)
			{
				const auto value = product[degree];
				product[degree - 3] ^= value;
				product[degree - 5] ^= value;
			}
			u32 result = 0;
			for (u64 i = 0; i < 5; ++i)
				result |= u32(product[i]) << (4 * i);
			return result;
		}

		static u32 towerPower(u32 value, u64 exponent)
		{
			u32 result = 1;
			while (exponent)
			{
				if (exponent & 1)
					result = towerMultiplyRaw(result, value);
				value = towerMultiplyRaw(value, value);
				exponent >>= 1;
			}
			return result;
		}

		static u32 towerGenerator()
		{
			static const u32 generator = []
			{
				constexpr u32 order = (1u << 20) - 1;
				constexpr std::array<u32, 5> primeFactors{ 3, 5, 11, 31, 41 };
				for (u32 candidate = 2; candidate <= order; ++candidate)
				{
					bool primitive = true;
					for (auto factor : primeFactors)
						if (towerPower(candidate, order / factor) == 1)
						{
							primitive = false;
							break;
						}
					if (primitive)
						return candidate;
				}
				throw RTE_LOC;
			}();
			return generator;
		}

		static u64 towerMinimalPolynomial()
		{
			std::array<u32, 21> polynomial{};
			polynomial[0] = 1;
			u32 root = towerGenerator();
			u64 degree = 0;
			for (; degree < 20; ++degree)
			{
				std::array<u32, 21> next{};
				for (u64 coefficient = 0; coefficient <= degree; ++coefficient)
				{
					next[coefficient] ^= towerMultiplyRaw(polynomial[coefficient], root);
					next[coefficient + 1] ^= polynomial[coefficient];
				}
				polynomial = next;
				root = towerMultiplyRaw(root, root);
			}
			if (root != towerGenerator())
				throw RTE_LOC;

			u64 result = 0;
			for (u64 coefficient = 0; coefficient <= degree; ++coefficient)
			{
				if (polynomial[coefficient] > 1)
					throw RTE_LOC;
				result |= u64(polynomial[coefficient]) << coefficient;
			}
			return result;
		}

		static std::pair<std::array<u32, 20>, std::array<u32, 20>> towerBasis()
		{
			// tower = forward * polynomial; polynomial = inverse * tower.
			std::array<u32, 20> forward{};
			u32 power = 1;
			for (u64 polynomialBit = 0; polynomialBit < 20; ++polynomialBit)
			{
				for (u64 towerBit = 0; towerBit < 20; ++towerBit)
					if ((power >> towerBit) & 1)
						forward[towerBit] ^= u32(1) << polynomialBit;
				power = towerMultiplyRaw(power, towerGenerator());
			}

			std::array<u64, 20> augmented{};
			for (u64 row = 0; row < 20; ++row)
				augmented[row] = forward[row] | (u64(1) << (20 + row));
			for (u64 column = 0; column < 20; ++column)
			{
				u64 pivot = column;
				while (pivot < 20 && ((augmented[pivot] >> column) & 1) == 0)
					++pivot;
				if (pivot == 20)
					throw RTE_LOC;
				if (pivot != column)
					std::swap(augmented[pivot], augmented[column]);
				for (u64 row = 0; row < 20; ++row)
					if (row != column && ((augmented[row] >> column) & 1))
						augmented[row] ^= augmented[column];
			}

			std::array<u32, 20> inverse{};
			for (u64 row = 0; row < 20; ++row)
				inverse[row] = static_cast<u32>(augmented[row] >> 20);
			return { forward, inverse };
		}

		static void xorExpression(
			Expression& destination,
			u64 offset,
			const Expression& source)
		{
			for (u64 i = 0; i < source.size(); ++i)
				destination[offset + i].insert(
					destination[offset + i].end(),
					source[i].begin(),
					source[i].end());
		}

		Expression buildKaratsuba(
			span<const u32> left,
			span<const u32> right)
		{
			const auto n = left.size();
			if (n != right.size() || n == 0)
				throw RTE_LOC;
			if (n == 1)
			{
				const auto leaf = static_cast<u32>(mLeaves.size());
				mLeaves.push_back({ left[0], right[0] });
				return Expression{ { leaf } };
			}

			const auto low = n / 2;
			const auto high = n - low;
			auto z0 = buildKaratsuba(left.subspan(0, low), right.subspan(0, low));
			auto z2 = buildKaratsuba(left.subspan(low, high), right.subspan(low, high));

			std::vector<u32> leftSum(high), rightSum(high);
			for (u64 i = 0; i < high; ++i)
			{
				leftSum[i] = left[low + i] ^ (i < low ? left[i] : 0);
				rightSum[i] = right[low + i] ^ (i < low ? right[i] : 0);
			}
			auto z1 = buildKaratsuba(leftSum, rightSum);

			Expression result(2 * n - 1);
			xorExpression(result, 0, z0);
			xorExpression(result, 2 * low, z2);
			xorExpression(result, low, z1);
			xorExpression(result, low, z0);
			xorExpression(result, low, z2);
			return result;
		}

		void buildTowerCircuit()
		{
			constexpr u64 pointCount = 9;
			const auto [forwardBasis, inverseBasis] = towerBasis();
			using PointProduct = std::array<Expression, pointCount>;
			PointProduct pointProduct;
			for (u64 point = 0; point < pointCount; ++point)
			{
				std::array<u32, 4> leftMask{};
				std::array<u32, 4> rightMask{};
				u8 power = 1;
				for (u64 coefficient = 0; coefficient < 5; ++coefficient)
				{
					for (u64 inputBit = 0; inputBit < 4; ++inputBit)
					{
						const auto contribution = gf16Multiply(1u << inputBit, power);
						for (u64 outputBit = 0; outputBit < 4; ++outputBit)
							if ((contribution >> outputBit) & 1)
							{
								leftMask[outputBit] ^= forwardBasis[4 * coefficient + inputBit];
								rightMask[outputBit] ^= forwardBasis[4 * coefficient + inputBit];
							}
					}
					power = gf16Multiply(power, static_cast<u8>(point));
				}

				auto raw = buildKaratsuba(leftMask, rightMask);
				for (u64 degree = 6; degree >= 4; --degree)
				{
					raw[degree - 4].insert(
						raw[degree - 4].end(), raw[degree].begin(), raw[degree].end());
					raw[degree - 3].insert(
						raw[degree - 3].end(), raw[degree].begin(), raw[degree].end());
				}
				for (u64 bit = 0; bit < 4; ++bit)
					pointProduct[point].push_back(std::move(raw[bit]));
			}

			std::array<std::array<u8, 2 * pointCount>, pointCount> inverse{};
			for (u64 row = 0; row < pointCount; ++row)
			{
				u8 power = 1;
				for (u64 column = 0; column < pointCount; ++column)
				{
					inverse[row][column] = power;
					power = gf16Multiply(power, static_cast<u8>(row));
				}
				inverse[row][pointCount + row] = 1;
			}
			for (u64 column = 0; column < pointCount; ++column)
			{
				u64 pivot = column;
				while (pivot < pointCount && inverse[pivot][column] == 0)
					++pivot;
				if (pivot == pointCount)
					throw RTE_LOC;
				if (pivot != column)
					std::swap(inverse[pivot], inverse[column]);
				const auto scale = gf16Power(inverse[column][column], 14);
				for (u64 entry = 0; entry < 2 * pointCount; ++entry)
					inverse[column][entry] = gf16Multiply(inverse[column][entry], scale);
				for (u64 row = 0; row < pointCount; ++row)
				{
					if (row == column)
						continue;
					const auto factor = inverse[row][column];
					for (u64 entry = 0; entry < 2 * pointCount; ++entry)
						inverse[row][entry] ^=
							gf16Multiply(factor, inverse[column][entry]);
				}
			}

			Expression towerProduct(20);
			for (u64 sourcePoint = 0; sourcePoint < pointCount; ++sourcePoint)
				for (u64 sourceBit = 0; sourceBit < 4; ++sourceBit)
				{
					std::array<u8, pointCount> coefficients{};
					const auto basis = static_cast<u8>(1u << sourceBit);
					for (u64 degree = 0; degree < pointCount; ++degree)
						coefficients[degree] = gf16Multiply(
							inverse[degree][pointCount + sourcePoint], basis);
					for (u64 degree = 8; degree >= 5; --degree)
					{
						coefficients[degree - 3] ^= coefficients[degree];
						coefficients[degree - 5] ^= coefficients[degree];
					}
					for (u64 coefficient = 0; coefficient < 5; ++coefficient)
						for (u64 outputBit = 0; outputBit < 4; ++outputBit)
							if ((coefficients[coefficient] >> outputBit) & 1)
								towerProduct[4 * coefficient + outputBit].insert(
									towerProduct[4 * coefficient + outputBit].end(),
									pointProduct[sourcePoint][sourceBit].begin(),
									pointProduct[sourcePoint][sourceBit].end());
				}

			mRawProduct.assign(20, {});
			for (u64 polynomialBit = 0; polynomialBit < 20; ++polynomialBit)
				for (u64 towerBit = 0; towerBit < 20; ++towerBit)
					if ((inverseBasis[polynomialBit] >> towerBit) & 1)
						mRawProduct[polynomialBit].insert(
							mRawProduct[polynomialBit].end(),
							towerProduct[towerBit].begin(),
							towerProduct[towerBit].end());

			for (auto& expression : mRawProduct)
			{
				std::sort(expression.begin(), expression.end());
				u64 output = 0;
				for (u64 input = 0; input < expression.size();)
				{
					u64 end = input + 1;
					while (end < expression.size() && expression[end] == expression[input])
						++end;
					if ((end - input) & 1)
						expression[output++] = expression[input];
					input = end;
				}
				expression.resize(output);
			}
		}

		static u64 polynomialRemainder(u64 value, u64 modulus)
		{
			const auto modulusDegree = std::bit_width(modulus) - 1;
			while (value && std::bit_width(value) - 1 >= modulusDegree)
			{
				const auto shift = std::bit_width(value) - 1 - modulusDegree;
				value ^= modulus << shift;
			}
			return value;
		}

		static u64 polynomialGcd(u64 a, u64 b)
		{
			while (b)
			{
				a = polynomialRemainder(a, b);
				std::swap(a, b);
			}
			return a;
		}

		static u64 squareMod(u64 value, u64 modulus)
		{
			u64 square = 0;
			for (u64 i = 0; value; ++i, value >>= 1)
				square ^= (value & 1) << (2 * i);
			return polynomialRemainder(square, modulus);
		}

		static bool isIrreducible(u64 modulus, u64 degree)
		{
			constexpr u64 x = 2;
			u64 power = x;
			for (u64 i = 1; i <= degree; ++i)
			{
				power = squareMod(power, modulus);
				if (i <= degree / 2 && polynomialGcd(power ^ x, modulus) != 1)
					return false;
			}
			return power == x;
		}

		static u64 findIrreducible(u64 degree)
		{
			if (degree == 1)
				return 0b11;
			const auto high = 1ull << degree;
			for (u64 low = 3; low < high; low += 2)
			{
				const auto candidate = high | low;
				if (isIrreducible(candidate, degree))
					return candidate;
			}
			throw std::runtime_error("Could not construct a binary field modulus. " LOCATION);
		}

		u32 reduce(u64 raw) const
		{
			const auto mask = mFieldBits == 32
				? std::numeric_limits<u32>::max()
				: (u32(1) << mFieldBits) - 1;
			u32 result = static_cast<u32>(raw) & mask;
			const auto high = raw >> mFieldBits;
			for (u64 byte = 0; byte < mReductionTable.size(); ++byte)
				result ^= mReductionTable[byte][(high >> (8 * byte)) & 0xff];
			return result;
		}

		OC_FORCEINLINE u64 multiplyPlainPairPacked(
			u32 left0,
			u32 left1,
			u32 right) const
		{
			// Two 20x20 carry-less products fit in one 64x64 product when the
			// left operands are separated by 40 bits. Their at-most-39-bit raw
			// products occupy disjoint output ranges [0,39) and [40,79).
			constexpr u64 rawMask = (u64(1) << 39) - 1;
			const auto raw = block(u64(left0) | (u64(left1) << 40))
				.clmulepi64_si128<0x00>(block(right));
			const auto low = raw.get<u64>(0);
			const auto high = raw.get<u64>(1);
			const auto raw0 = low & rawMask;
			const auto raw1 = ((low >> 40) | (high << 24)) & rawMask;
			return u64(reduce(raw0)) | (u64(reduce(raw1)) << 32);
		}

		u32 square(u32 value) const
		{
			u64 raw = 0;
			for (u64 i = 0; i < mFieldBits; ++i)
				raw ^= u64((value >> i) & 1) << (2 * i);
			return reduce(raw);
		}

		macoro::task<> multiplyFields(
			span<const u32> left,
			span<const u32> right,
			span<u32> product,
			coproto::Socket& socket)
		{
			if (left.size() != mNumRows || right.size() != mNumRows || product.size() != mNumRows)
				throw RTE_LOC;

			const auto leafCount = mLeaves.size();
			const auto productCount = mNumRows * leafCount;
			BitVector leftBits(productCount);
			BitVector rightBits(productCount);
			BitVector products(productCount);
			for (u64 row = 0; row < mNumRows; ++row)
			{
				for (u64 leaf = 0; leaf < leafCount; ++leaf)
				{
					const auto index = row * leafCount + leaf;
					leftBits[index] = std::popcount(left[row] & mLeaves[leaf].mLeftMask) & 1;
					rightBits[index] = std::popcount(right[row] & mLeaves[leaf].mRightMask) & 1;
				}
			}

			co_await mMultiplier.multiplyBits(leftBits, rightBits, products, socket);
			for (u64 row = 0; row < mNumRows; ++row)
			{
				u64 raw = 0;
				for (u64 coefficient = 0; coefficient < mRawProduct.size(); ++coefficient)
				{
					u8 bitShare = 0;
					for (auto leaf : mRawProduct[coefficient])
						bitShare ^= products[row * leafCount + leaf];
					raw ^= u64(bitShare) << coefficient;
				}
				product[row] = reduce(raw);
			}
		}

	public:
		struct Powers
		{
			std::vector<std::vector<u32>> mValues;
		};

		DpfMult mMultiplier;

		void init(u64 partyIdx, u64 numRows, u64 degree, u64 fieldBits)
		{
			if (partyIdx > 1 || numRows == 0 || degree == 0 || fieldBits == 0 || fieldBits > 32)
				throw std::invalid_argument("Invalid Waterfall hash parameters. " LOCATION);

			mPartyIdx = partyIdx;
			mNumRows = numRows;
			mDegree = degree;
			mFieldBits = fieldBits;
			mOddPowerCount = degree > 2 ? (degree - 2) / 2 : 0;
			mModulus = fieldBits == 20 ? towerMinimalPolynomial() : findIrreducible(fieldBits);
			for (u64 byte = 0; byte < mReductionTable.size(); ++byte)
				for (u64 value = 0; value < mReductionTable[byte].size(); ++value)
					mReductionTable[byte][value] = static_cast<u32>(polynomialRemainder(
						value << (mFieldBits + 8 * byte),
						mModulus));
			mLeaves.clear();
			if (fieldBits == 20)
				buildTowerCircuit();
			else
			{
				std::vector<u32> variables(fieldBits);
				for (u64 i = 0; i < fieldBits; ++i)
					variables[i] = u32(1) << i;
				mRawProduct = buildKaratsuba(variables, variables);
			}
			mMultiplier.init(mPartyIdx, mNumRows * mOddPowerCount * mLeaves.size());
		}

		u64 karatsubaProductCount() const
		{
			return mLeaves.size();
		}

		u64 fieldBits() const
		{
			return mFieldBits;
		}

		u64 degree() const
		{
			return mDegree;
		}

		u64 baseOtCount() const
		{
			return mMultiplier.baseOtCount();
		}

		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const BitVector& baseChoices)
		{
			mMultiplier.setBaseOts(baseSendOts, recvBaseOts, baseChoices);
		}

		Powers preparePlain(span<const u32> input) const
		{
			if (input.size() != mNumRows)
				throw RTE_LOC;
			Powers powers;
			powers.mValues.resize(mDegree, std::vector<u32>(mNumRows));
			const auto mask = mFieldBits == 32 ? std::numeric_limits<u32>::max() : (u32(1) << mFieldBits) - 1;
			for (u64 row = 0; row < mNumRows; ++row)
			{
				powers.mValues[0][row] = 1;
				if (mDegree > 1)
					powers.mValues[1][row] = input[row] & mask;
			}
			for (u64 exponent = 2; exponent < mDegree; ++exponent)
			{
				for (u64 row = 0; row < mNumRows; ++row)
				{
					if ((exponent & 1) == 0)
						powers.mValues[exponent][row] = square(powers.mValues[exponent / 2][row]);
					else
						powers.mValues[exponent][row] = multiplyPlain(
							powers.mValues[1][row], powers.mValues[exponent - 1][row]);
				}
			}
			return powers;
		}

		macoro::task<Powers> prepare(
			MatrixView<const u8> input,
			coproto::Socket& socket)
		{
			if (input.rows() != mNumRows || input.cols() * 8 < mFieldBits)
				throw RTE_LOC;
			Powers powers;
			powers.mValues.resize(mDegree, std::vector<u32>(mNumRows));
			const auto mask = mFieldBits == 32 ? std::numeric_limits<u32>::max() : (u32(1) << mFieldBits) - 1;
			for (u64 row = 0; row < mNumRows; ++row)
			{
				powers.mValues[0][row] = mPartyIdx ? 1 : 0;
				u32 value = 0;
				copyBytesMin(value, input[row]);
				if (mDegree > 1)
					powers.mValues[1][row] = value & mask;
			}

			for (u64 exponent = 2; exponent < mDegree; ++exponent)
			{
				if ((exponent & 1) == 0)
				{
					for (u64 row = 0; row < mNumRows; ++row)
						powers.mValues[exponent][row] = square(powers.mValues[exponent / 2][row]);
				}
				else
				{
					co_await multiplyFields(
						powers.mValues[1],
						powers.mValues[exponent - 1],
						powers.mValues[exponent],
						socket);
				}
			}
			co_return powers;
		}

		void evaluate(
			const Powers& powers,
			MatrixView<const u32> coefficients,
			u64 numSets,
			span<const u64> partitionSizes,
			MatrixView<u32> output) const
		{
			const auto w = partitionSizes.size();
			if (powers.mValues.size() != mDegree ||
				mNumRows % numSets != 0 ||
				coefficients.rows() != numSets * w ||
				coefficients.cols() != mDegree ||
				output.rows() != mNumRows || output.cols() != w)
				throw RTE_LOC;

			const auto rowsPerSet = mNumRows / numSets;
			for (u64 row = 0; row < mNumRows; ++row)
			{
				const auto set = row / rowsPerSet;
				for (u64 partition = 0; partition < w; ++partition)
				{
					u32 value = 0;
					for (u64 exponent = 0; exponent < mDegree; ++exponent)
						value ^= multiplyPlain(
							powers.mValues[exponent][row],
							coefficients(set * w + partition, exponent));
					const auto bits = std::bit_width(partitionSizes[partition] - 1);
					output(row, partition) = value & ((u32(1) << bits) - 1);
				}
			}
		}

		u32 multiplyPlain(u32 left, u32 right) const
		{
			const auto raw = block(left).clmulepi64_si128<0x00>(block(right));
			return reduce(raw.get<u64>(0));
		}

		u32 evaluatePlain(
			span<const u32> coefficients,
			u32 input,
			u64 rangeSize) const
		{
			if (coefficients.size() != mDegree || rangeSize == 0 ||
				(rangeSize & (rangeSize - 1)) != 0 || rangeSize > (1ull << mFieldBits))
				throw RTE_LOC;

			u32 value = coefficients[mDegree - 1];
			for (u64 exponent = mDegree - 1; exponent; --exponent)
				value = multiplyPlain(value, input) ^ coefficients[exponent - 1];
			return value & static_cast<u32>(rangeSize - 1);
		}

		void evaluatePointPair(
			span<const u32> coefficients0,
			span<const u32> coefficients1,
			u64 rangeSize0,
			u64 rangeSize1,
			span<const u32> input,
			span<u32> output0,
			span<u32> output1) const
		{
			if (coefficients0.size() != mDegree || coefficients1.size() != mDegree ||
				input.size() != output0.size() || output0.size() != output1.size() ||
				rangeSize0 == 0 || rangeSize1 == 0 ||
				(rangeSize0 & (rangeSize0 - 1)) != 0 ||
				(rangeSize1 & (rangeSize1 - 1)) != 0 ||
				rangeSize0 > (1ull << mFieldBits) || rangeSize1 > (1ull << mFieldBits))
				throw RTE_LOC;

			if (mFieldBits != 20)
			{
				for (u64 point = 0; point < input.size(); ++point)
				{
					output0[point] = evaluatePlain(coefficients0, input[point], rangeSize0);
					output1[point] = evaluatePlain(coefficients1, input[point], rangeSize1);
				}
				return;
			}

			const auto outputMask0 = static_cast<u32>(rangeSize0 - 1);
			const auto outputMask1 = static_cast<u32>(rangeSize1 - 1);
			u64 point = 0;
			for (; point + 8 <= input.size(); point += 8)
			{
				const auto last = mDegree - 1;
				const u64 lastCoefficient = u64(coefficients0[last]) |
					(u64(coefficients1[last]) << 32);
				std::array<u64, 8> value{
					lastCoefficient, lastCoefficient, lastCoefficient, lastCoefficient,
					lastCoefficient, lastCoefficient, lastCoefficient, lastCoefficient
				};
				for (u64 exponent = last; exponent; --exponent)
				{
					const u64 coefficient = u64(coefficients0[exponent - 1]) |
						(u64(coefficients1[exponent - 1]) << 32);
					for (u64 lane = 0; lane < value.size(); ++lane)
						value[lane] = multiplyPlainPairPacked(
							static_cast<u32>(value[lane]),
							static_cast<u32>(value[lane] >> 32),
							input[point + lane]) ^ coefficient;
				}
				for (u64 lane = 0; lane < value.size(); ++lane)
				{
					output0[point + lane] = static_cast<u32>(value[lane]) & outputMask0;
					output1[point + lane] = static_cast<u32>(value[lane] >> 32) & outputMask1;
				}
			}
			for (; point < input.size(); ++point)
			{
				output0[point] = evaluatePlain(coefficients0, input[point], rangeSize0);
				output1[point] = evaluatePlain(coefficients1, input[point], rangeSize1);
			}
		}

		void evaluateConsecutivePair(
			span<const u32> coefficients0,
			span<const u32> coefficients1,
			u64 rangeSize0,
			u64 rangeSize1,
			span<u32> output0,
			span<u32> output1) const
		{
			if (coefficients0.size() != mDegree || coefficients1.size() != mDegree ||
				output0.size() != output1.size() || rangeSize0 == 0 || rangeSize1 == 0 ||
				(rangeSize0 & (rangeSize0 - 1)) != 0 ||
				(rangeSize1 & (rangeSize1 - 1)) != 0 ||
				rangeSize0 > (1ull << mFieldBits) || rangeSize1 > (1ull << mFieldBits) ||
				output0.size() > (1ull << mFieldBits))
				throw RTE_LOC;

			if (mFieldBits != 20)
			{
				for (u64 point = 0; point < output0.size(); ++point)
				{
					output0[point] = evaluatePlain(coefficients0, static_cast<u32>(point), rangeSize0);
					output1[point] = evaluatePlain(coefficients1, static_cast<u32>(point), rangeSize1);
				}
				return;
			}

			const auto coefficientMask = u64(std::numeric_limits<u32>::max());
			const auto outputMask0 = static_cast<u32>(rangeSize0 - 1);
			const auto outputMask1 = static_cast<u32>(rangeSize1 - 1);
			u64 point = 0;
			for (; point + 8 <= output0.size(); point += 8)
			{
				const auto last = mDegree - 1;
				const u64 lastCoefficient = u64(coefficients0[last]) |
					(u64(coefficients1[last]) << 32);
				u64 value0 = lastCoefficient;
				u64 value1 = lastCoefficient;
				u64 value2 = lastCoefficient;
				u64 value3 = lastCoefficient;
				u64 value4 = lastCoefficient;
				u64 value5 = lastCoefficient;
				u64 value6 = lastCoefficient;
				u64 value7 = lastCoefficient;
				for (u64 exponent = last; exponent; --exponent)
				{
					const u64 coefficient = u64(coefficients0[exponent - 1]) |
						(u64(coefficients1[exponent - 1]) << 32);
					value0 = multiplyPlainPairPacked(value0 & coefficientMask, value0 >> 32, static_cast<u32>(point + 0)) ^ coefficient;
					value1 = multiplyPlainPairPacked(value1 & coefficientMask, value1 >> 32, static_cast<u32>(point + 1)) ^ coefficient;
					value2 = multiplyPlainPairPacked(value2 & coefficientMask, value2 >> 32, static_cast<u32>(point + 2)) ^ coefficient;
					value3 = multiplyPlainPairPacked(value3 & coefficientMask, value3 >> 32, static_cast<u32>(point + 3)) ^ coefficient;
					value4 = multiplyPlainPairPacked(value4 & coefficientMask, value4 >> 32, static_cast<u32>(point + 4)) ^ coefficient;
					value5 = multiplyPlainPairPacked(value5 & coefficientMask, value5 >> 32, static_cast<u32>(point + 5)) ^ coefficient;
					value6 = multiplyPlainPairPacked(value6 & coefficientMask, value6 >> 32, static_cast<u32>(point + 6)) ^ coefficient;
					value7 = multiplyPlainPairPacked(value7 & coefficientMask, value7 >> 32, static_cast<u32>(point + 7)) ^ coefficient;
				}
				output0[point + 0] = static_cast<u32>(value0) & outputMask0;
				output0[point + 1] = static_cast<u32>(value1) & outputMask0;
				output0[point + 2] = static_cast<u32>(value2) & outputMask0;
				output0[point + 3] = static_cast<u32>(value3) & outputMask0;
				output0[point + 4] = static_cast<u32>(value4) & outputMask0;
				output0[point + 5] = static_cast<u32>(value5) & outputMask0;
				output0[point + 6] = static_cast<u32>(value6) & outputMask0;
				output0[point + 7] = static_cast<u32>(value7) & outputMask0;
				output1[point + 0] = static_cast<u32>(value0 >> 32) & outputMask1;
				output1[point + 1] = static_cast<u32>(value1 >> 32) & outputMask1;
				output1[point + 2] = static_cast<u32>(value2 >> 32) & outputMask1;
				output1[point + 3] = static_cast<u32>(value3 >> 32) & outputMask1;
				output1[point + 4] = static_cast<u32>(value4 >> 32) & outputMask1;
				output1[point + 5] = static_cast<u32>(value5 >> 32) & outputMask1;
				output1[point + 6] = static_cast<u32>(value6 >> 32) & outputMask1;
				output1[point + 7] = static_cast<u32>(value7 >> 32) & outputMask1;
			}
			for (; point < output0.size(); ++point)
			{
				output0[point] = evaluatePlain(coefficients0, static_cast<u32>(point), rangeSize0);
				output1[point] = evaluatePlain(coefficients1, static_cast<u32>(point), rangeSize1);
			}
		}
	};
}
