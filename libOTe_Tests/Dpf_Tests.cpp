#include "Dpf_Tests.h"
#include "libOTe/Dpf/RegularDpf.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include "libOTe/Dpf/SparseDpf.h"
#include <algorithm>
#include <numeric>
#include "libOTe/Dpf/TernaryDpf.h"
#include "cryptoTools/Common/TestCollection.h"
#include "libOTe/Tools/CoeffCtx.h"
#include "libOTe/Dpf/RevCuckooDmpf.h"
#include "libOTe/Dpf/RevCuckoo/Equality.h"
#include "libOTe/Dpf/RevCuckoo/GoldreichHash.h"
#include "libOTe/Tools/Field/Fp.h"
#include "libOTe/Dpf/SumDmpf.h"

using namespace oc;

void RegularDpf_Multiply_Test(const CLP& cmd)
{
#if defined(ENABLE_REGULAR_DPF) || defined(ENABLE_SPARSE_DPF)
	u64 n = 13;
	PRNG prng(block(231234, 321312));
	std::array<oc::DpfMult, 2> dpf;
	dpf[0].init(0, n);
	dpf[1].init(1, n);

	std::array<std::vector<std::array<block, 2>>, 2> sendOts;
	std::array<std::vector<block>, 2> recvOts;
	std::array<BitVector, 2> choices;
	for (u64 i = 0; i < 2; ++i)
	{
		sendOts[i].resize(n);
		recvOts[i].resize(n);
		choices[i].resize(n);
		choices[i].randomize(prng);
		prng.get(sendOts[i].data(), sendOts[i].size());
		for (u64 j = 0; j < n; ++j)
			recvOts[i][j] = sendOts[i][j][choices[i][j]];
	}

	dpf[0].setBaseOts(sendOts[0], recvOts[1], choices[1]);
	dpf[1].setBaseOts(sendOts[1], recvOts[0], choices[0]);

	{
		u64 i = 0;
		u64 a0 = dpf[0].mChoiceBits[i];
		block A0 = block(-a0, -a0);
		auto c00 = dpf[0].mRecvOts[i];

		auto b1 = dpf[0].mSendOts[i][0] ^ dpf[0].mSendOts[i][1];
		auto c10 = dpf[0].mSendOts[i][0];

		// C0' = c00+c10+a0b1
		auto C0 = c00 ^ c10 ^ (b1 & A0);

		u64 a1 = dpf[1].mChoiceBits[i];
		block A1 = block(-a1, -a1);
		auto c01 = dpf[1].mRecvOts[i];

		auto b0 = dpf[1].mSendOts[i][1] ^ dpf[1].mSendOts[i][1];
		auto c11 = dpf[1].mSendOts[i][0];

		// C0' = c00+c10+a0b1
		auto C1 = c11 ^ c01 ^ (b0 & A1);

		auto a = a0 ^ a1;
		auto B = b0 ^ b1;
		auto C = C0 ^ C1;

		if (a == 0 && C != oc::ZeroBlock)
			throw RTE_LOC;
		if (a == 1 && C != B)
			throw RTE_LOC;
	}

	auto sock = coproto::LocalAsyncSocket::makePair();

	for (u64 i = 0; i < 10; ++i)
	{
		//std::cout << "-=========================-" std::endl;

		for (u64 i = 0; i < 2; ++i)
		{
			choices[i].randomize(prng);
			prng.get(sendOts[i].data(), sendOts[i].size());
			for (u64 j = 0; j < n; ++j)
				recvOts[i][j] = sendOts[i][j][choices[i][j]];
		}
		dpf[0].setBaseOts(sendOts[0], recvOts[1], choices[1]);
		dpf[1].setBaseOts(sendOts[1], recvOts[0], choices[0]);

		BitVector x0(n), x1(n);
		x0.randomize(prng);
		x1.randomize(prng);
		std::vector<block> xy0(n), xy1(n), y0(n), y1(n);

		prng.get(y0.data(), y0.size());
		prng.get(y1.data(), y1.size());

		macoro::sync_wait(macoro::when_all_ready(
			dpf[0].multiply(x0, y0, xy0, sock[0]),
			dpf[1].multiply(x1, y1, xy1, sock[1])
		));

		for (u64 j = 0; j < n; ++j)
		{

			u64 x = x0[j] ^ x1[j];
			auto y = y0[j] ^ y1[j];
			auto xy = xy0[j] ^ xy1[j];
			auto exp = block(-x, -x) & y;
			if (xy != exp)
			{
				std::cout << "i " << i << std::endl;
				std::cout << "act " << xy << " " << xy0[j] << " + " << xy1[j] << std::endl;
				std::cout << "exp " << exp << std::endl;
				throw RTE_LOC;
			}
		}
	}
#else
	throw UnitTestSkipped("ENABLE_REGULAR_DPF and ENABLE_SPARSE_DPF not defined.");
#endif
}

void RegularDpf_MultByte_Test(const CLP& cmd)
{
#if defined(ENABLE_REGULAR_DPF) || defined(ENABLE_SPARSE_DPF)

	{
		u64 n = 10;
		u64 bitCount = 3;
		Matrix<u8> m(n, divCeil(bitCount, 8));
		Matrix<u8> d(n, divCeil(bitCount, 8));
		std::vector<u8> b(divCeil(n * bitCount, 8));

		PRNG prng(block(231234, 321312));
		for (u64 i = 0; i < n; ++i)
		{
			for (u64 j = 0; j < bitCount; ++j)
			{
				*BitIterator(m[i].data(), j) = prng.getBit();
			}
		}

		DpfMult::packBits(b, m, bitCount);
		DpfMult::unpackBits(d, b, bitCount);
		if (m != d)
			throw RTE_LOC;
	}


for (auto m : { 16ull, 3ull,8ull, 13ull, 33ull, 233ull })
{

	u64 n = 13;
	u64 m8 = divCeil(m, 8);

	PRNG prng(block(231234, 321312));
	std::array<oc::DpfMult, 2> dpf;
	dpf[0].init(0, n);
	dpf[1].init(1, n);

	std::array<std::vector<std::array<block, 2>>, 2> sendOts;
	std::array<std::vector<block>, 2> recvOts;
	std::array<BitVector, 2> choices;
	for (u64 i = 0; i < 2; ++i)
	{
		sendOts[i].resize(n);
		recvOts[i].resize(n);
		choices[i].resize(n);
	}

	auto sock = coproto::LocalAsyncSocket::makePair();

	for (u64 i = 0; i < 4; ++i)
	{
		//std::cout << "-=========================-" std::endl;

		for (u64 i = 0; i < 2; ++i)
		{
			choices[i].randomize(prng);
			prng.get(sendOts[i].data(), sendOts[i].size());
			for (u64 j = 0; j < n; ++j)
				recvOts[i][j] = sendOts[i][j][choices[i][j]];
		}
		dpf[0].setBaseOts(sendOts[0], recvOts[1], choices[1]);
		dpf[1].setBaseOts(sendOts[1], recvOts[0], choices[0]);

		BitVector x0(n), x1(n);
		x0.randomize(prng);
		x1.randomize(prng);
		Matrix<u8> xy0(n, m8), xy1(n, m8), y0(n, m8), y1(n, m8);

		//prng.get(y0.data(), y0.size());
		//prng.get(y1.data(), y1.size());
		for (u64 i = 0; i < n; ++i)
		{
			for (u64 j = 0; j < m; ++j)
			{
				*BitIterator(y0[i].data(), j) = prng.getBit();
				*BitIterator(y1[i].data(), j) = prng.getBit();
			}
		}

		macoro::sync_wait(macoro::when_all_ready(
			dpf[0].multiply(m, x0.getSpan<u8>(), y0, xy0, sock[0]),
			dpf[1].multiply(m, x1.getSpan<u8>(), y1, xy1, sock[1])
		));

		for (u64 j = 0; j < n; ++j)
		{
			for (u64 i = 0; i < m8; ++i)
			{

				u64 x = x0[j] ^ x1[j];
				auto y = y0[j][i] ^ y1[j][i];
				u64 xy = xy0[j][i] ^ xy1[j][i];
				auto exp = x * y;
				if (xy != exp)
				{
					std::cout << " m " << m << std::endl;
					std::cout << "j " << j << " i " << i << std::endl;
					std::cout << "act " << int(xy) << "=" << int(xy0[j][i]) << " + " << int(xy1[j][i]) << std::endl;
					std::cout << "exp " << int(exp) << std::endl;
					throw RTE_LOC;
				}
			}
		}
	}
}
#else
	throw UnitTestSkipped("ENABLE_REGULAR_DPF and ENABLE_SPARSE_DPF not defined.");
#endif
}


void RegularDpf_MultBit_Test(const CLP& cmd)
{
#if defined(ENABLE_REGULAR_DPF) || defined(ENABLE_SPARSE_DPF)


	u64 n = 1311;

	PRNG prng(block(231234, 321312));
	std::array<oc::DpfMult, 2> dpf;
	dpf[0].init(0, n);
	dpf[1].init(1, n);

	std::array<std::vector<std::array<block, 2>>, 2> sendOts;
	std::array<std::vector<block>, 2> recvOts;
	std::array<BitVector, 2> choices;
	for (u64 i = 0; i < 2; ++i)
	{
		sendOts[i].resize(n);
		recvOts[i].resize(n);
		choices[i].resize(n);
	}

	auto sock = coproto::LocalAsyncSocket::makePair();

	for (u64 i = 0; i < 4; ++i)
	{
		//std::cout << "-=========================-" std::endl;

		for (u64 i = 0; i < 2; ++i)
		{
			choices[i].randomize(prng);
			prng.get(sendOts[i].data(), sendOts[i].size());
			for (u64 j = 0; j < n; ++j)
				recvOts[i][j] = sendOts[i][j][choices[i][j]];
		}
		dpf[0].setBaseOts(sendOts[0], recvOts[1], choices[1]);
		dpf[1].setBaseOts(sendOts[1], recvOts[0], choices[0]);

		BitVector x0(n), x1(n);
		BitVector xy0(n), xy1(n), y0(n), y1(n);
		x0.randomize(prng);
		x1.randomize(prng);
		y0.randomize(prng);
		y1.randomize(prng);

		macoro::sync_wait(macoro::when_all_ready(
			dpf[0].multiplyBits(x0, y0, xy0, sock[0]),
			dpf[1].multiplyBits(x1, y1, xy1, sock[1])
		));

		for (u64 j = 0; j < n; ++j)
		{

			u64 x = x0[j] ^ x1[j];
			auto y = y0[j] ^ y1[j];
			u64 xy = xy0[j] ^ xy1[j];
			auto exp = x & y;
			if (xy != exp)
			{
				std::cout << "j " << j << " i " << i << std::endl;
				std::cout << "x   " << int(x) << "=" << int(x0[j]) << " + " << int(x1[j]) << std::endl;
				std::cout << "y   " << int(y) << "=" << int(y0[j]) << " + " << int(y1[j]) << std::endl;
				std::cout << "act " << int(xy) << "=" << int(xy0[j]) << " + " << int(xy1[j]) << std::endl;
				std::cout << "exp " << int(exp) << std::endl;
				throw RTE_LOC;
			}
		}
	}
#else
	throw UnitTestSkipped("ENABLE_REGULAR_DPF and ENABLE_SPARSE_DPF not defined.");
#endif
}

struct CoeffCtxOpaque;
struct OpaqueCtr {};
class Opaque
{
private:
	Opaque() = default;
	Opaque(const Opaque&) = default;
	Opaque& operator=(const Opaque&) = default;

	u32 mData;
	friend class CoeffCtxOpaque;
public:
	Opaque(OpaqueCtr) {}
};


struct CoeffCtxOpaque
{

	void plus(Opaque& ret, const Opaque& lhs, const Opaque& rhs) { ret.mData = lhs.mData + rhs.mData; }
	void minus(Opaque& ret, const Opaque& lhs, const Opaque& rhs) { ret.mData = lhs.mData - rhs.mData; }
	void mul(Opaque& ret, const Opaque& lhs, const Opaque& rhs) { ret.mData = lhs.mData * rhs.mData; }
	bool eq(Opaque& lhs, Opaque& rhs) { return lhs.mData == rhs.mData; }

	template<typename F>
	bool isField() { return false; }

	// is G characteristic 2 where x+x = 0?
	template<typename G>
	bool characteristicTwo() { return false; }

	void mulConst(Opaque& ret, const Opaque& x) { ret.mData = x.mData; }

	template<typename F>
	u64 bitSize() { return sizeof(F) * 8; }

	BitVector binaryDecomposition(const Opaque& x) { return { (u8*)&x.mData, bitSize<Opaque>() }; }

	bool active = true;
	void fromBlock(Opaque& ret, const block& b) { ret.mData = b.get<u8>(0); }

	// return the F element with value 2^power
	OC_FORCEINLINE void powerOfTwo(Opaque& ret, u64 power) {
		one(ret);
		ret.mData <<= power;
	}

	template<typename T>
	struct Vec
	{
		std::unique_ptr<T[]> mData;
		u64 mSize = 0;
		u64 size() const { return mSize; }
		auto begin() { return mData.get(); }
		auto end() { return mData.get() + size(); }
		T& operator[](u64 i) { return mData[i]; }
	};
	// A vector like type that can be used to store
	// temporaries. 
	// 
	// must have:
	//  * size()
	//  * operator[i] that returns the i'th F element reference.
	//  * begin() iterator over the F elements
	//  * end() iterator over the F elements
	/*template<typename F>
	using Vec = std::unique_ptr<F>;*/

	// resize Vec<F>
	void resize(Vec<Opaque>& f, u64 size) {
		Vec<Opaque> ff;
		ff.mSize = size;
		ff.mData.reset(new Opaque[size]);
		for (u64 i = 0; i < f.size(); ++i)
			ff[i] = f[i];
		f = std::move(ff);
	}

	template<typename F>
	auto makeVec(u64 size) { Vec<F>f; resize(f, size); return f; }

	template<typename F>
	auto make() { return F{}; }

	// the size of F when serialized.
	template<typename F>
	u64 byteSize() { return sizeof(F); }

	// copy a single F element.
	void copy(Opaque& dst, const Opaque& src) { dst.mData = src.mData; }


	// copy [begin,...,end) into [dstBegin, ...)
	// the iterators will point to the same types, i.e. F
	template<typename SrcIter, typename DstIter>
	void copy(
		SrcIter begin,
		SrcIter end,
		DstIter dstBegin)
	{
		using F1 = std::remove_reference_t<decltype(*begin)>;
		using F2 = std::remove_reference_t<decltype(*dstBegin)>;
		static_assert(std::is_trivially_copyable<F1>::value, "memcpy is used so must be trivially_copyable.");
		static_assert(std::is_same_v<F1, F2>, "src and destication types are not the same.");

		memcpy((F2 * __restrict) & *dstBegin, (F1 * __restrict) & *begin, std::distance(begin, end) * sizeof(F1));
	}

	// deserialize [begin,...,end) into  [dstBegin, ...)
	// begin will be a u8 pointer/iterator.
	// dstBegin will be an F pointer/iterator
	template<typename SrcIter, typename DstIter>
	void deserialize(SrcIter&& begin, SrcIter&& end, DstIter&& dstBegin)
	{
		// as written this function is a bit more general than strictly neccessary
		// due to serialize(...) redirecting here.
		using SrcType = std::remove_reference_t<decltype(*begin)>;

		// how many source elem do we have?
		auto srcN = std::distance(begin, end);
		if (srcN)
		{
			// the source size in bytes
			auto n = srcN * sizeof(SrcType);

			// make sure the pointer math work with this iterator type.
			auto beginU8 = (u8*)&*begin;
			auto dstBeginU8 = (u8*)&*dstBegin;

			// memcpy the bytes
			std::memcpy(dstBeginU8, beginU8, n);
		}
	}

	// serialize [begin,...,end) into  [dstBegin, ...)
	// begin will be an F pointer/iterator
	// dstBegin will be a byte pointer/iterator.
	template<typename SrcIter, typename DstIter>
	void serialize(SrcIter&& begin, SrcIter&& end, DstIter&& dstBegin)
	{
		deserialize(begin, end, dstBegin);
	}


	template<typename F, typename Iter>
	auto restrictPtr(Iter iter) { return iter; }


	template<typename Iter>
	void zero(Iter begin, Iter end)
	{
		while (begin != end)
			zero(*begin++);
	}
	// fill the range [begin,..., end) with zeros. 
	// begin will be an F pointer/iterator.
	void zero(Opaque& x)
	{
		x.mData = 0;
	}


	// fill the range [begin,..., end) with ones. 
	// begin will be an F pointer/iterator.
	template<typename Iter>
	void one(Iter begin, Iter end)
	{
		while (begin != end)
			one(*begin++);
	}

	void one(Opaque& x)
	{
		x.mData = 1;
	}

	// convert F into a string
	std::string str(Opaque& f)
	{
		std::stringstream ss;
		ss << f.mData;
		return ss.str();
	}

	void mask(Opaque& ret, const Opaque& x, const block& mask)
	{
		ret.mData = x.mData & mask.get<u32>(0);
	}
};

template<typename T>
void setActive(T&& t, bool b) {}
void setActive(CoeffCtxOpaque& t, bool b) { t.active = b; }



template<typename T, typename Ctx>
void RegularDpf_Proto_Test_impl(const oc::CLP& cmd)
{

#ifdef ENABLE_REGULAR_DPF

	PRNG prng(block(231234, cmd.getOr("seed", 7645456)));
	u64 domain = cmd.getOr("domain", 211);
	u64 numPoints = cmd.getOr("numPoints", 11);
	std::vector<u64> points0(numPoints);
	std::vector<u64> points1(numPoints);
	typename Ctx::template Vec<T> values0;
	typename Ctx::template Vec<T> values1;
	Ctx ctx;

	ctx.resize(values0, numPoints);
	ctx.resize(values1, numPoints);
	for (u64 i = 0; i < numPoints; ++i)
	{
		points1[i] = prng.get<u64>();
		points0[i] = (prng.get<u64>() % domain) ^ points1[i];
		ctx.fromBlock(values0[i], prng.get());
		ctx.fromBlock(values1[i], prng.get());

		auto vv = ctx.template make<T>();
		auto zero = ctx.template make<T>();
		auto neg = ctx.template make<T>();
		ctx.zero(zero);
		ctx.plus(vv, values0[i], values1[i]);
		ctx.minus(neg, zero, vv);

		//std::cout << "point " << i << " p = "
		//	<< (points0[i] ^ points1[i]) << ", v = "
		//	<< ctx.str(vv) << " = -"<< ctx.str(neg) << std::endl;
	}
	setActive(ctx, false);

	std::array<oc::RegularDpf<T, Ctx>, 2> dpf;
	dpf[0].init(0, domain, numPoints);
	dpf[1].init(1, domain, numPoints);

	auto baseCount = dpf[0].baseOtCount();

	std::array<std::vector<block>, 2> baseRecv;
	std::array<std::vector<std::array<block, 2>>, 2> baseSend;
	std::array<BitVector, 2> baseChoice;
	baseRecv[0].resize(baseCount);
	baseRecv[1].resize(baseCount);
	baseSend[0].resize(baseCount);
	baseSend[1].resize(baseCount);
	baseChoice[0].resize(baseCount);
	baseChoice[1].resize(baseCount);
	baseChoice[0].randomize(prng);
	baseChoice[1].randomize(prng);
	for (u64 i = 0; i < baseCount; ++i)
	{
		baseSend[0][i] = prng.get();
		baseSend[1][i] = prng.get();
		baseRecv[0][i] = baseSend[1][i][baseChoice[0][i]];
		baseRecv[1][i] = baseSend[0][i][baseChoice[1][i]];
	}
	dpf[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
	dpf[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

	using Vec = typename Ctx::template Vec<T>;

	std::array<Vec, 2> output;
	std::array<Matrix<u8>, 2> tags;
	ctx.resize(output[0], numPoints * domain);
	ctx.resize(output[1], numPoints * domain);
	//output[0].resize(numPoints, domain);
	//output[1].resize(numPoints, domain);
	tags[0].resize(numPoints, domain);
	tags[1].resize(numPoints, domain);

	auto sock = coproto::LocalAsyncSocket::makePair();
	auto r = macoro::sync_wait(macoro::when_all_ready(
		dpf[0].expand(points0, values0, prng, sock[0], [&](auto k, auto i, auto&& v, auto&& t) { ctx.copy(output[0][k * domain + i], v); tags[0](k, i) = t.template get<u8>(0) & 1; }, ctx),
		dpf[1].expand(points1, values1, prng, sock[1], [&](auto k, auto i, auto&& v, auto&& t) { ctx.copy(output[1][k * domain + i], v); tags[1](k, i) = t.template get<u8>(0) & 1; }, ctx)
	));
	std::get<0>(r).result();
	std::get<1>(r).result();

	for (u64 i = 0; i < domain; ++i)
	{
		for (u64 k = 0; k < numPoints; ++k)
		{
			auto p = points0[k] ^ points1[k];
			auto t = i == p ? 1 : 0;
			auto tAct = tags[0][k][i] ^ tags[1][k][i];

			auto act = ctx.template make<T>();
			ctx.plus(act, output[0][k* domain +i], output[1][k * domain + i]);
			auto exp = ctx.template make<T>();
			if(t)
				ctx.plus(exp, values0[k], values1[k]);
			else
				ctx.zero(exp);

			if (!ctx.eq(exp, act))
			{
				std::cout
					<< k << " " <<i <<"\n"
					<< ctx.str(output[0][k * domain + i]) << " + "
					<< ctx.str(output[1][k * domain + i]) << " = "
					<< ctx.str(act) << " != "
					<< ctx.str(exp) << std::endl;
				throw RTE_LOC;
			}
			if (t != tAct)
				throw RTE_LOC;
		}
	}
#else
	throw UnitTestSkipped("ENABLE_REGULAR_DPF not defined.");
#endif
}

void RegularDpf_Proto_Test(const CLP& cmd)
{
	//RegularDpf_Proto_Test_impl<block, CoeffCtxGF2>(cmd);
	//RegularDpf_Proto_Test_impl<u64, CoeffCtxInteger>(cmd);
	using F = F12289;
	RegularDpf_Proto_Test_impl<F, CoeffCtxFp>(cmd);

	RegularDpf_Proto_Test_impl<Opaque, CoeffCtxOpaque>(cmd);
}

void RegularDpf_Puncture_Test(const oc::CLP& cmd)
{
#ifdef ENABLE_REGULAR_DPF
	PRNG prng(block(231234, 321312));
	u64 domain = cmd.getOr("domain", 8);
	u64 numPoints = cmd.getOr("numPoints", 1);
	std::vector<u64> points0(numPoints);
	std::vector<u64> points1(numPoints);
	for (u64 i = 0; i < numPoints; ++i)
	{
		points1[i] = prng.get<u64>();
		points0[i] = (prng.get<u64>() % domain) ^ points1[i];
	}

	std::array<oc::RegularDpf<block>, 2> dpf;
	dpf[0].init(0, domain, numPoints);
	dpf[1].init(1, domain, numPoints);

	auto baseCount = dpf[0].baseOtCount();

	std::array<std::vector<block>, 2> baseRecv;
	std::array<std::vector<std::array<block, 2>>, 2> baseSend;
	std::array<BitVector, 2> baseChoice;
	baseRecv[0].resize(baseCount);
	baseRecv[1].resize(baseCount);
	baseSend[0].resize(baseCount);
	baseSend[1].resize(baseCount);
	baseChoice[0].resize(baseCount);
	baseChoice[1].resize(baseCount);
	baseChoice[0].randomize(prng);
	baseChoice[1].randomize(prng);
	for (u64 i = 0; i < baseCount; ++i)
	{
		baseSend[0][i] = prng.get();
		baseSend[1][i] = prng.get();
		baseRecv[0][i] = baseSend[1][i][baseChoice[0][i]];
		baseRecv[1][i] = baseSend[0][i][baseChoice[1][i]];
	}
	dpf[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
	dpf[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

	std::array<Matrix<block>, 2> output;
	std::array<Matrix<u8>, 2> tags;
	output[0].resize(numPoints, domain);
	output[1].resize(numPoints, domain);
	tags[0].resize(numPoints, domain);
	tags[1].resize(numPoints, domain);

	auto sock = coproto::LocalAsyncSocket::makePair();
	macoro::sync_wait(macoro::when_all_ready(
		dpf[0].expand(points0, std::vector<block>{}, prng, sock[0], [&](auto k, auto i, auto v, block t) { output[0](k, i) = v; tags[0](k, i) = t.get<u8>(0) & 1; }),
		dpf[1].expand(points1, std::vector<block>{}, prng, sock[1], [&](auto k, auto i, auto v, block t) { output[1](k, i) = v; tags[1](k, i) = t.get<u8>(0) & 1; })
	));


	bool failed = false;
	for (u64 i = 0; i < domain; ++i)
	{
		for (u64 k = 0; k < numPoints; ++k)
		{
			auto p = points0[k] ^ points1[k];
			auto act = output[0][k][i] ^ output[1][k][i];
			auto t = i == p ? 1 : 0;
			auto tAct = tags[0][k][i] ^ tags[1][k][i];
			if (t == 0 && act != ZeroBlock)
				throw RTE_LOC;

			if (t == 1 && act == ZeroBlock)
				failed = true;

			if (t != tAct)
				throw RTE_LOC;
		}
	}

	if (failed)
		throw RTE_LOC;

#else
	throw UnitTestSkipped("ENABLE_REGULAR_DPF not defined.");
#endif
}

template<typename T, typename CoeffCtx>
void RegularDpf_keyGen_impl(const oc::CLP& cmd)
{
#ifdef ENABLE_REGULAR_DPF


	PRNG prng(block(231234, 321312));
	u64 domain = cmd.getOr("domain", 211);
	u64 numPoints = cmd.getOr("numPoints", 11);
	std::vector<u64> points(numPoints);
	std::vector<u64> points0(numPoints);
	std::vector<u64> points1(numPoints);

	// Convert to use CoeffCtx for value operations
	CoeffCtx ctx;
	typename CoeffCtx::template Vec<T> values;
	typename CoeffCtx::template Vec<T> values0;
	typename CoeffCtx::template Vec<T> values1;
	ctx.resize(values, numPoints);
	ctx.resize(values0, numPoints);
	ctx.resize(values1, numPoints);

	for (u64 i = 0; i < numPoints; ++i)
	{
		points[i] = prng.get<u64>() % domain;
		points1[i] = prng.get<u64>();
		points0[i] = points[i] ^ points1[i];

		// Use CoeffCtx for value operations instead of hardcoded block operations
		ctx.fromBlock(values0[i], prng.get());
		ctx.fromBlock(values1[i], prng.get());
		ctx.plus(values[i], values0[i], values1[i]);
	}

	std::array<oc::RegularDpf<T, CoeffCtx>, 2> dpf;
	dpf[0].init(0, domain, numPoints);
	dpf[1].init(1, domain, numPoints);

	auto baseCount = dpf[0].baseOtCount();

	std::array<std::vector<block>, 2> baseRecv;
	std::array<std::vector<std::array<block, 2>>, 2> baseSend;
	std::array<BitVector, 2> baseChoice;
	baseRecv[0].resize(baseCount);
	baseRecv[1].resize(baseCount);
	baseSend[0].resize(baseCount);
	baseSend[1].resize(baseCount);
	baseChoice[0].resize(baseCount);
	baseChoice[1].resize(baseCount);
	baseChoice[0].randomize(prng);
	baseChoice[1].randomize(prng);
	for (u64 i = 0; i < baseCount; ++i)
	{
		baseSend[0][i] = prng.get();
		baseSend[1][i] = prng.get();
		baseRecv[0][i] = baseSend[1][i][baseChoice[0][i]];
		baseRecv[1][i] = baseSend[0][i][baseChoice[1][i]];
	}
	dpf[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
	dpf[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

	// Convert output to use CoeffCtx
	typename CoeffCtx::template Vec<T> output0;
	typename CoeffCtx::template Vec<T> output1;
	ctx.resize(output0, numPoints * domain);
	ctx.resize(output1, numPoints * domain);
	std::array<Matrix<u8>, 2> tags;
	tags[0].resize(numPoints, domain);
	tags[1].resize(numPoints, domain);

	std::array<RegularDpfKey, 2> key, key2, key3;

	auto sock = coproto::LocalAsyncSocket::makePair();

	prng.SetSeed(block(214234, 2341234));

	// generate the keys using MPC
	macoro::sync_wait(macoro::when_all_ready(
		dpf[0].keyGen(points0, values0, prng, key[0], sock[0], ctx),
		dpf[1].keyGen(points1, values1, prng, key[1], sock[1], ctx)
	));

	// real code should use:
	//     prng.SetSeed(sysRandomSeed());
	prng.SetSeed(block(214234, 2341234));

	// generate the seeds.
	RegularDpf<T, CoeffCtx>::keyGen(domain, span<u64>(points), values, prng, span<RegularDpfKey>(key2), ctx);

	if (key[0] != key2[0])
	{
		// print the keys
		std::cout << "key[0] != key2[0]" << std::endl;
		std::cout << "cw ";
		for (u64 i = 0; i < key[0].mCorrectionWords.rows(); ++i)
		{
			for (u64 j = 0; j < key[0].mCorrectionWords.cols(); ++j)
			{
				if (key[0].mCorrectionWords(i, j) != key2[0].mCorrectionWords(i, j) || 
					key[0].mCorrectionBits(i, j) != key2[0].mCorrectionBits(i, j))
					std::cout << Color::Red;
				std::cout
					<< key[0].mCorrectionWords(i, j) << "." << int(key[0].mCorrectionBits(i, j)) << " v "
					<< key2[0].mCorrectionWords(i, j) << "." << int(key2[0].mCorrectionBits(i, j)) << " " << Color::Default;
			}
			std::cout << std::endl;
		}
		std::cout << " leaf ";
		for (u64 i = 0; i < key[0].mLeafVals.size(); ++i)
		{

			if (key[0].mLeafVals[i] != key2[0].mLeafVals[i])
				std::cout << Color::Red;
			std::cout << int(key[0].mLeafVals[i]) << " v " << int(key2[0].mLeafVals[i]) << " " << Color::Default;
		}
		std::cout << std::endl;
		throw RTE_LOC;
	}
	if (key[1] != key2[1])
		throw RTE_LOC;

	// serialize the seeds.
	std::vector<u8> buff0(key2[0].sizeBytes());
	std::vector<u8> buff1(key2[1].sizeBytes());
	key2[0].toBytes(buff0);
	key2[1].toBytes(buff1);

	// send buffer...
	// deserialize
	key3[0].resize<T>(domain, numPoints, ctx);
	key3[1].resize<T>(domain, numPoints, ctx);
	key3[0].fromBytes(buff0);
	key3[1].fromBytes(buff1);

	if (key[0] != key3[0])
		throw RTE_LOC;
	if (key[1] != key3[1])
		throw RTE_LOC;

	// expand the dpf
	RegularDpf<T, CoeffCtx>::expand(0, domain, key3[0], [&](auto k, auto i, auto&& v, block t) {
		ctx.copy(output0[k * domain + i], v);
		tags[0](k, i) = t.get<u8>(0) & 1;
		}, ctx);
	RegularDpf<T, CoeffCtx>::expand(1, domain, key3[1], [&](auto k, auto i, auto&& v, block t) {
		ctx.copy(output1[k * domain + i], v);
		tags[1](k, i) = t.get<u8>(0) & 1;
		}, ctx);

	// check the results
	for (u64 i = 0; i < domain; ++i)
	{
		for (u64 k = 0; k < numPoints; ++k)
		{
			auto p = points0[k] ^ points1[k];

			auto act = ctx.template make<T>();
			ctx.plus(act, output0[k * domain + i], output1[k * domain + i]);

			auto t = i == p ? 1 : 0;
			auto tAct = tags[0][k][i] ^ tags[1][k][i];

			auto exp = ctx.template make<T>();
			if (t)
				ctx.plus(exp, values0[k], values1[k]);
			else
				ctx.zero(exp);

			if (!ctx.eq(exp, act))
			{
				throw RTE_LOC;
			}
			if (t != tAct)
				throw RTE_LOC;
		}
	}

	//PRNG prng(block(231234, 321312));
	//u64 domain = cmd.getOr("domain", 211);
	//u64 numPoints = cmd.getOr("numPoints", 11);
	//std::vector<u64> points(numPoints);
	//std::vector<u64> points0(numPoints);
	//std::vector<u64> points1(numPoints);
	//std::vector<T> values(numPoints);
	//std::vector<T> values0(numPoints);
	//std::vector<T> values1(numPoints);
	//for (u64 i = 0; i < numPoints; ++i)
	//{
	//	points[i] = prng.get<u64>() % domain;
	//	points1[i] = prng.get<u64>();
	//	points0[i] = points[i] ^ points1[i];
	//	values0[i] = prng.get();
	//	values1[i] = prng.get();
	//	values[i] = values0[i] ^ values1[i];
	//}

	//std::array<oc::RegularDpf<block>, 2> dpf;
	//dpf[0].init(0, domain, numPoints);
	//dpf[1].init(1, domain, numPoints);

	//auto baseCount = dpf[0].baseOtCount();

	//std::array<std::vector<block>, 2> baseRecv;
	//std::array<std::vector<std::array<block, 2>>, 2> baseSend;
	//std::array<BitVector, 2> baseChoice;
	//baseRecv[0].resize(baseCount);
	//baseRecv[1].resize(baseCount);
	//baseSend[0].resize(baseCount);
	//baseSend[1].resize(baseCount);
	//baseChoice[0].resize(baseCount);
	//baseChoice[1].resize(baseCount);
	//baseChoice[0].randomize(prng);
	//baseChoice[1].randomize(prng);
	//for (u64 i = 0; i < baseCount; ++i)
	//{
	//	baseSend[0][i] = prng.get();
	//	baseSend[1][i] = prng.get();
	//	baseRecv[0][i] = baseSend[1][i][baseChoice[0][i]];
	//	baseRecv[1][i] = baseSend[0][i][baseChoice[1][i]];
	//}
	//dpf[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
	//dpf[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

	//std::array<Matrix<block>, 2> output;
	//std::array<Matrix<u8>, 2> tags;
	//output[0].resize(numPoints, domain);
	//output[1].resize(numPoints, domain);
	//tags[0].resize(numPoints, domain);
	//tags[1].resize(numPoints, domain);

	//std::array<RegularDpfKey, 2> key, key2, key3;

	//auto sock = coproto::LocalAsyncSocket::makePair();

	//prng.SetSeed(block(214234, 2341234));

	//// generate the keys using MPC
	//macoro::sync_wait(macoro::when_all_ready(
	//	dpf[0].keyGen(points0, values0, prng, key[0], sock[0]),
	//	dpf[1].keyGen(points1, values1, prng, key[1], sock[1])
	//));






	//// real code should use:
	////     prng.SetSeed(sysRandomSeed());
	//prng.SetSeed(block(214234, 2341234));

	//// generate the seeds.
	//RegularDpf<block>::keyGen(domain, span<u64>(points), span<block>(values), prng, span<RegularDpfKey>(key2));

	//if (key[0] != key2[0])
	//{
	//	// pritn the keys
	//	std::cout << "key[0] != key2[0]" << std::endl;
	//	std::cout << "cw ";
	//	for (u64 i = 0; i < key[0].mCorrectionWords.rows(); ++i)
	//	{
	//		for (u64 j = 0; j < key[0].mCorrectionWords.cols(); ++j)
	//		{
	//			std::cout 
	//				<< key[0].mCorrectionWords(i, j) << "." << int(key[0].mCorrectionBits(i,j)) << " v " 
	//				<< key2[0].mCorrectionWords(i, j) << "." << int(key2[0].mCorrectionBits(i, j)) << " ";
	//		}
	//		std::cout << std::endl;
	//	}
	//	std::cout << " leaf ";
	//	for (u64 i = 0; i < key[0].mLeafVals.size(); ++i)
	//	{
	//		std::cout << int(key[0].mLeafVals[i]) << " v " << int(key2[0].mLeafVals[i]) << " ";
	//	}


	//	throw RTE_LOC;
	//}
	//if (key[1] != key2[1])
	//	throw RTE_LOC;

	//// serialize the seeds.
	//std::vector<u8> buff0(key2[0].sizeBytes());
	//std::vector<u8> buff1(key2[1].sizeBytes());
	//key2[0].toBytes(buff0);
	//key2[1].toBytes(buff1);

	//// send buffer...
	//// deserialize
	//key3[0].resize<block>(domain, numPoints);
	//key3[1].resize<block>(domain, numPoints);
	//key3[0].fromBytes(buff0);
	//key3[1].fromBytes(buff1);

	//if (key[0] != key3[0])
	//	throw RTE_LOC;
	//if (key[1] != key3[1])
	//	throw RTE_LOC;

	//// expand the dpf
	//RegularDpf<block>::expand(0, domain, key3[0], [&](auto k, auto i, auto v, block t) { output[0](k, i) = v; tags[0](k, i) = t.get<u8>(0) & 1; });
	//RegularDpf<block>::expand(1, domain, key3[1], [&](auto k, auto i, auto v, block t) { output[1](k, i) = v; tags[1](k, i) = t.get<u8>(0) & 1; });

	//// check the results
	//for (u64 i = 0; i < domain; ++i)
	//{
	//	for (u64 k = 0; k < numPoints; ++k)
	//	{
	//		auto p = points0[k] ^ points1[k];
	//		auto act = output[0][k][i] ^ output[1][k][i];
	//		auto t = i == p ? 1 : 0;
	//		auto tAct = tags[0][k][i] ^ tags[1][k][i];
	//		auto exp = t ? (values0[k] ^ values1[k]) : ZeroBlock;
	//		if (exp != act)
	//		{

	//			throw RTE_LOC;
	//		}
	//		if (t != tAct)
	//			throw RTE_LOC;
	//	}
	//}

#else
	throw UnitTestSkipped("ENABLE_REGULAR_DPF not defined.");
#endif
}

void RegularDpf_keyGen_Test(const oc::CLP& cmd)
{
	RegularDpf_keyGen_impl<block, CoeffCtxGF2>(cmd);
	RegularDpf_keyGen_impl<u64, CoeffCtxInteger>(cmd);
}

void SumDmpf_Proto_Test(const oc::CLP& cmd)
{

#ifdef ENABLE_REGULAR_DPF

	PRNG prng(block(231234, 321312));
	u64 domain = cmd.getOr("domain", 211);
	u64 numPoints = cmd.getOr("numPoints", 11);
	u64 numSets = cmd.getOr("numSets", 3);
	Matrix<u64> points(numSets, numPoints);
	Matrix<u64> points0(numSets, numPoints);
	Matrix<u64> points1(numSets, numPoints);
	Matrix<block> values(numSets, numPoints);
	Matrix<block> values0(numSets, numPoints);
	Matrix<block> values1(numSets, numPoints);
	for (u64 i = 0; i < numSets; ++i)
	{
		std::set<u64> uniquePoints;
		for(u64 j = 0; j < numPoints; ++j)
		{
			u64 p;
			do {
				p = prng.get<u64>() % domain;
			}
			while (!uniquePoints.insert(p).second);

			points(i, j) = p;
			points1(i, j) = prng.get<u64>();
			points0(i, j) = points(i, j) ^ points1(i, j);
			values0(i, j) = prng.get();
			values1(i, j) = prng.get();
			values(i, j) = values0(i, j) ^ values1(i, j);
		}
		points(i) = prng.get<u64>() % domain;
		points1(i) = prng.get<u64>();
		points0(i) = points(i) ^ points1(i);
		values0(i) = prng.get();
		values1(i) = prng.get();
		values(i) = values0(i) ^ values1(i);
	}

	std::array<oc::SumDmpf<block>, 2> dpf;
	dpf[0].init(0, domain, numPoints, numSets);
	dpf[1].init(1, domain, numPoints, numSets);

	auto baseCount = dpf[0].baseOtCount();

	std::array<std::vector<block>, 2> baseRecv;
	std::array<std::vector<std::array<block, 2>>, 2> baseSend;
	std::array<BitVector, 2> baseChoice;
	baseRecv[0].resize(baseCount);
	baseRecv[1].resize(baseCount);
	baseSend[0].resize(baseCount);
	baseSend[1].resize(baseCount);
	baseChoice[0].resize(baseCount);
	baseChoice[1].resize(baseCount);
	baseChoice[0].randomize(prng);
	baseChoice[1].randomize(prng);
	for (u64 i = 0; i < baseCount; ++i)
	{
		baseSend[0][i] = prng.get();
		baseSend[1][i] = prng.get();
		baseRecv[0][i] = baseSend[1][i][baseChoice[0][i]];
		baseRecv[1][i] = baseSend[0][i][baseChoice[1][i]];
	}
	dpf[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
	dpf[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

	std::array<Matrix<block>, 2> output;
	std::array<Matrix<u8>, 2> tags;
	output[0].resize(numSets, domain);
	output[1].resize(numSets, domain);
	tags[0].resize(numSets, domain);
	tags[1].resize(numSets, domain);

	auto sock = coproto::LocalAsyncSocket::makePair();


	// Expand the DPF to generate numSets instances of secret shared vectors
	auto r = macoro::sync_wait(macoro::when_all_ready(
		dpf[0].expand(points0, values0, prng, sock[0],
			[&](auto setIdx, auto i, auto&& v, auto&& t) {
				output[0](setIdx, i) = v;
				tags[0](setIdx, i) = t.template get<u8>(0) & 1;
			}),
		dpf[1].expand(points1, values1, prng, sock[1],
			[&](auto setIdx, auto i, auto&& v, auto&& t) {
				output[1](setIdx, i) = v;
				tags[1](setIdx, i) = t.template get<u8>(0) & 1;
			})
	));
	std::get<0>(r).result();
	std::get<1>(r).result();

	// Verify correctness for each set
	for (u64 setIdx = 0; setIdx < numSets; ++setIdx)
	{
		std::vector<block> expectedValue(domain);

		for (u64 pointIdx = 0; pointIdx < numPoints; ++pointIdx)
		{
			auto p = points0(setIdx, pointIdx) ^ points1(setIdx, pointIdx);
			expectedValue[p] ^= values0(setIdx, pointIdx) ^ values1(setIdx, pointIdx);
		}

		for (u64 i = 0; i < domain; ++i)
		{
			// Check if this domain position should be active for any point in this set
			bool isActive = expectedValue[i] != ZeroBlock;


			auto actualValue = output[0](setIdx, i) ^ output[1](setIdx, i);
			auto actualTag = tags[0](setIdx, i) ^ tags[1](setIdx, i);
			auto expectedTag = isActive ? 1 : 0;

			if (actualValue != expectedValue[i])
			{
				std::cout << "Value mismatch at set " << setIdx << ", position " << i << std::endl;
				std::cout << "Expected: " << expectedValue[i] << std::endl;
				std::cout << "Actual: " << actualValue << std::endl;
				throw RTE_LOC;
			}

			if (actualTag != expectedTag)
			{
				std::cout << "Tag mismatch at set " << setIdx << ", position " << i << std::endl;
				std::cout << "Expected: " << expectedTag << std::endl;
				std::cout << "Actual: " << actualTag << std::endl;
				throw RTE_LOC;
			}
		}
	}



#else
	throw UnitTestSkipped("ENABLE_REGULAR_DPF not defined.");
#endif
}

// round the index a to the "bitwise" nearest point in set.
u64 round(u64 a, span<u32> set, u64 bitCount)
{
	a &= (1ull << bitCount) - 1;
	for (u64 b = bitCount - 1; b < bitCount; --b)
	{
		auto mask = 1ull << b;
		auto aa = a & mask;

		// the start of the section half
		auto mid = std::lower_bound(set.begin(), set.end(), mask, [](auto s, auto mask) -> bool {
			return !(s & mask);
			});

		// we want the second half but there is no second half or
		// we want the first  half but there is no first  half.
		// if so, then we need to round our index
		if ((aa && (mid == set.end())) ||
			(!aa && (mid== set.begin())))
		{
			a ^= mask;
			aa ^= mask;
		}

		if (aa)
			set = span<u32>(mid, set.end());
		else
			set = span<u32>(set.begin(), mid);
	}
	return a;
}

void SparseDpf_Mtx_Test(const oc::CLP& cmd)
{
#ifdef ENABLE_SPARSE_DPF

	PRNG prng(block(32324, 2342));
	u64 numPoints = 11;
	u64 domain = 1773;
	u64 dense = 4;
	u64 fraction = 16;

	auto index{ std::vector<u64>(numPoints) };
	auto value{ std::vector<block>(numPoints) };
	std::array points{ std::vector<u64>(numPoints),std::vector<u64>(numPoints) };
	std::array values{ std::vector<block>(numPoints), std::vector<block>(numPoints) };
	oc::SparseDpf dpf[2];
	Matrix<u32> sparsePoints(numPoints, domain / fraction);

	for (u64 j = 0; j < numPoints; ++j)
	{
		std::vector<u32> set(domain);
		std::iota(set.begin(), set.end(), 0);
		for (u64 i = 0; i < sparsePoints.cols(); ++i)
		{
			auto k = prng.get<u32>() % set.size();
			std::swap(set[k], set.back());
			sparsePoints(j, i) = set.back();
			set.pop_back();
		}
	}

	for (u64 i = 0; i < sparsePoints.rows(); ++i)
	{
		std::sort(sparsePoints[i].begin(), sparsePoints[i].end());
		index[i] = prng.get<u64>() % sparsePoints.cols();
		value[i] = prng.get();
		//auto alpha = sparsePoints(i, index[i]);
		//std::cout << "alpha " << alpha << " " << oc::BitVector((u8*)&alpha, log2ceil(domain)) << std::endl;
		points[0][i] = prng.get();
		points[1][i] = points[0][i] ^ sparsePoints(i, index[i]);
		values[0][i] = prng.get();
		values[1][i] = values[0][i] ^ value[i];
	}


	dpf[0].init(0, numPoints, domain, dense);
	dpf[1].init(1, numPoints, domain, dense);
	auto sock = coproto::LocalAsyncSocket::makePair();

	auto baseCount = dpf[0].baseOtCount();

	std::array<std::vector<std::array<block, 2>>, 2> sendOts;
	std::array<std::vector<block>, 2> recvOts;
	std::array<BitVector, 2> choices;
	for (u64 i = 0; i < 2; ++i)
	{
		sendOts[i].resize(baseCount);
		recvOts[i].resize(baseCount);
		choices[i].resize(baseCount);
		choices[i].randomize(prng);
		prng.get(sendOts[i].data(), sendOts[i].size());
		for (u64 j = 0; j < baseCount; ++j)
			recvOts[i][j] = sendOts[i][j][choices[i][j]];
	}

	dpf[0].setBaseOts(sendOts[0], recvOts[1], choices[1]);
	dpf[1].setBaseOts(sendOts[1], recvOts[0], choices[0]);


	std::array<Matrix<block>, 2> out;
	std::array<Matrix<u8>, 2> tags;
	out[0].resize(numPoints, sparsePoints.cols());
	out[1].resize(numPoints, sparsePoints.cols());
	tags[0].resize(numPoints, sparsePoints.cols());
	tags[1].resize(numPoints, sparsePoints.cols());
	auto r = macoro::sync_wait(
		macoro::when_all_ready(
			dpf[0].expand(points[0], values[0], [&](auto k, auto i, auto v, auto t) { out[0](k, i) = v; tags[0](k, i) = t; }, prng, sparsePoints, sock[0]),
			dpf[1].expand(points[1], values[1], [&](auto k, auto i, auto v, auto t) { out[1](k, i) = v; tags[1](k, i) = t; }, prng, sparsePoints, sock[1])
		));


	std::get<0>(r).result();
	std::get<1>(r).result();

	for (u64 i = 0; i < numPoints; ++i)
	{
		for (u64 j = 0; j < sparsePoints.cols(); ++j)
		{
			auto active = index[i] == j ? 1 : 0;

			auto tag = tags[0](i, j) ^ tags[1](i, j);
			if (tag != active)
				throw RTE_LOC;

			auto act = out[0](i, j) ^ out[1](i, j);
			auto exp = active ? value[i] : ZeroBlock;
			if (act != exp)
				throw RTE_LOC;
		}
	}
#else
	throw UnitTestSkipped("ENABLE_SPARSE_DPF not defined.");
#endif
}

void SparseDpf_Vec_Test(const oc::CLP& cmd)
{
#ifdef ENABLE_SPARSE_DPF

	PRNG prng(block(32324, 2342));
	for (auto dense : { /*0,*/ 4 })
	{

		for (u64 t = 0; t < 2; ++t)
		{

			u64 numPoints = 8;
			u64 domain = 1773;
			//u64 dense = 0;
			u64 fraction = 16;

			if (t == 0) {
				domain = 32;
				numPoints = 1;
			}

			auto index{ std::vector<u64>(numPoints) };
			auto value{ std::vector<block>(numPoints) };
			std::array points{ std::vector<u64>(numPoints),std::vector<u64>(numPoints) };
			std::array values{ std::vector<block>(numPoints), std::vector<block>(numPoints) };
			oc::SparseDpf dpf[2];
			std::vector<std::vector<u32>> sparsePoints(numPoints);// , domain / fraction);



			if (t == 0)
			{
				sparsePoints[0] = { 0, 4, 5, 9, 12, 18, 26, 30 };
				if (numPoints == 8)
				{
					sparsePoints[1] = { 2, 10, 13, 14, 15, 17, 24, 31 };
					sparsePoints[2] = { 7, 8, 11, 21, 22, 23, 25, 27 };
					sparsePoints[3] = { 1, 3, 6, 16, 19, 20, 28, 29 };
					sparsePoints[4] = { 0, 3, 7, 14, 26, 29 };
					sparsePoints[5] = { 1, 4, 5, 9, 12, 15, 17, 21, 28, 31 };
					sparsePoints[6] = { 6, 10, 11, 13, 16, 19, 22, 23, 27, 30 };
					sparsePoints[7] = { 2, 8, 18, 20, 24, 25 };
				}
				std::vector<u32> point = { u32(~0ul), u32(2ul), u32(23ul), u32(~0ul), u32(~0ul), u32(9ul), u32(~0ul), u32(8ul) };

				for (u64 i = 0; i < numPoints; ++i)
				{
					point[i] = round(point[i], sparsePoints[i], log2ceil(domain));
					index[i] = std::lower_bound(sparsePoints[i].begin(), sparsePoints[i].end(), point[i]) -
						sparsePoints[i].begin();
					if (index[i] == sparsePoints[i].size())
						throw RTE_LOC;
					value[i] = prng.get();
					points[0][i] = prng.get();
					points[1][i] = points[0][i] ^ (index[i] == ~0ull ? 32 : sparsePoints[i][index[i]]);
					values[0][i] = prng.get();
					values[1][i] = values[0][i] ^ value[i];
				}

			}
			else
			{

				for (u64 j = 0; j < numPoints; ++j)
				{
					sparsePoints[j].resize(domain / fraction + prng.get<u8>() % 20);
					std::vector<u32> set(domain);
					std::iota(set.begin(), set.end(), 0);
					for (u64 i = 0; i < sparsePoints[j].size(); ++i)
					{
						auto k = prng.get<u32>() % set.size();
						std::swap(set[k], set.back());
						sparsePoints[j][i] = set.back();
						set.pop_back();
					}
				}

				for (u64 i = 0; i < numPoints; ++i)
				{
					std::sort(sparsePoints[i].begin(), sparsePoints[i].end());
					index[i] = prng.get<u64>() % sparsePoints[i].size();
					value[i] = prng.get();
					//auto alpha = sparsePoints(i, index[i]);
					//std::cout << "alpha " << alpha << " " << oc::BitVector((u8*)&alpha, log2ceil(domain)) << std::endl;
					points[0][i] = prng.get();
					points[1][i] = points[0][i] ^ sparsePoints[i][index[i]];
					values[0][i] = prng.get();
					values[1][i] = values[0][i] ^ value[i];
				}


			}



			dpf[0].init(0, numPoints, domain, dense);
			dpf[1].init(1, numPoints, domain, dense);
			auto sock = coproto::LocalAsyncSocket::makePair();

			auto baseCount = dpf[0].baseOtCount();

			std::array<std::vector<std::array<block, 2>>, 2> sendOts;
			std::array<std::vector<block>, 2> recvOts;
			std::array<BitVector, 2> choices;
			for (u64 i = 0; i < 2; ++i)
			{
				sendOts[i].resize(baseCount);
				recvOts[i].resize(baseCount);
				choices[i].resize(baseCount);
				choices[i].randomize(prng);
				prng.get(sendOts[i].data(), sendOts[i].size());
				for (u64 j = 0; j < baseCount; ++j)
					recvOts[i][j] = sendOts[i][j][choices[i][j]];
			}

			dpf[0].setBaseOts(sendOts[0], recvOts[1], choices[1]);
			dpf[1].setBaseOts(sendOts[1], recvOts[0], choices[0]);


			std::array<std::vector<std::vector<block>>, 2> out;
			std::array<std::vector<std::vector<u8>>, 2> tags;
			out[0].resize(numPoints);
			out[1].resize(numPoints);
			tags[0].resize(numPoints);
			tags[1].resize(numPoints);
			for (u64 i = 0; i < numPoints; ++i)
			{
				out[0][i].resize(sparsePoints[i].size());
				out[1][i].resize(sparsePoints[i].size());
				tags[0][i].resize(sparsePoints[i].size());
				tags[1][i].resize(sparsePoints[i].size());
			}

			auto r = macoro::sync_wait(
				macoro::when_all_ready(
					dpf[0].expand(points[0], values[0], [&](auto k, auto i, auto v, auto t) { out[0][k][i] = v; tags[0][k][i] = t; }, prng, sparsePoints, sock[0]),
					dpf[1].expand(points[1], values[1], [&](auto k, auto i, auto v, auto t) { out[1][k][i] = v; tags[1][k][i] = t; }, prng, sparsePoints, sock[1])
				));


			std::get<0>(r).result();
			std::get<1>(r).result();

			for (u64 i = 0; i < numPoints; ++i)
			{
				for (u64 j = 0; j < sparsePoints[i].size(); ++j)
				{
					auto active = index[i] == j ? 1 : 0;

					auto tag = tags[0][i][j] ^ tags[1][i][j];
					auto act = out[0][i][j] ^ out[1][i][j];
					auto exp = active ? value[i] : ZeroBlock;
					if (act != exp)
					{
						std::cout << "idx " << index[i] << std::endl;
						std::cout << "loc " << sparsePoints[i][index[i]] << std::endl;
						std::cout << "act " << act << " " << int(tag) << std::endl;
						std::cout << "exp " << exp << " " << int(active) << std::endl;
						throw RTE_LOC;
					}

					if (tag != active)
						throw RTE_LOC;
				}
			}
		}
	}
#else
	throw UnitTestSkipped("ENABLE_SPARSE_DPF not defined.");
#endif
}


template<typename F, typename Ctx>
void TernaryDpf_Proto_Test_(const oc::CLP& cmd)
{
#ifdef ENABLE_TERNARY_DPF

	PRNG prng(block(231234, 321312));
	u64 depth = cmd.getOr("depth", 3);
	u64 domain = ipow(3, depth) - 3;
	u64 numPoints = cmd.getOr("numPoints", 17);
	std::vector<F3x32> points0(numPoints);
	std::vector<F3x32> points1(numPoints);
	std::vector<F3x32> points(numPoints);
	std::vector<F> values0(numPoints);
	std::vector<F> values1(numPoints);
	Ctx ctx;
	for (u64 i = 0; i < numPoints; ++i)
	{
		points[i] = F3x32(prng.get<u64>() % domain);
		points1[i] = F3x32(prng.get<u64>() % domain);
		points0[i] = points[i] - points1[i];
		//std::cout << points[i] << " = " << points0[i] <<" + "<< points1[i] << std::endl;
		values0[i] = prng.get();
		values1[i] = prng.get();
		//ctx.minus(points0[i], points[i], points1[i];)
	}

	std::array<oc::TernaryDpf<F, Ctx>, 2> dpf;
	dpf[0].init(0, domain, numPoints);
	dpf[1].init(1, domain, numPoints);

	auto baseCount = dpf[0].baseOtCount();

	std::array<std::vector<block>, 2> baseRecv;
	std::array<std::vector<std::array<block, 2>>, 2> baseSend;
	std::array<BitVector, 2> baseChoice;
	baseRecv[0].resize(baseCount);
	baseRecv[1].resize(baseCount);
	baseSend[0].resize(baseCount);
	baseSend[1].resize(baseCount);
	baseChoice[0].resize(baseCount);
	baseChoice[1].resize(baseCount);
	baseChoice[0].randomize(prng);
	baseChoice[1].randomize(prng);
	for (u64 i = 0; i < baseCount; ++i)
	{
		baseSend[0][i] = prng.get();
		baseSend[1][i] = prng.get();
		baseRecv[0][i] = baseSend[1][i][baseChoice[0][i]];
		baseRecv[1][i] = baseSend[0][i][baseChoice[1][i]];
	}
	dpf[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
	dpf[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

	std::array<Matrix<F>, 2> output;
	std::array<Matrix<u8>, 2> tags;
	output[0].resize(numPoints, domain);
	output[1].resize(numPoints, domain);
	tags[0].resize(numPoints, domain);
	tags[1].resize(numPoints, domain);

	auto sock = coproto::LocalAsyncSocket::makePair();
	macoro::sync_wait(macoro::when_all_ready(
		dpf[0].expand(points0, values0, [&](auto k, auto i, auto v, auto t) { output[0](k, i) = v; tags[0](k, i) = t; }, prng, sock[0]),
		dpf[1].expand(points1, values1, [&](auto k, auto i, auto v, auto t) { output[1](k, i) = v; tags[1](k, i) = t; }, prng, sock[1])
	));


	for (u64 i = 0; i < domain; ++i)
	{
		F3x32 I(i);
		for (u64 k = 0; k < numPoints; ++k)
		{
			F act;
			ctx.plus(act, output[0][k][i], output[1][k][i]);
			auto t = I == points[k] ? 1 : 0;
			auto tAct = tags[0][k][i] ^ tags[1][k][i];
			F exp;
			if (t)
				ctx.plus(exp, values0[k], values1[k]);
			else
				ctx.zero(&exp, &exp + 1);

			if (exp != act)
			{
				std::cout << "i " << i << "=" << F3x32(i) << " " << t << std::endl;
				std::cout << "exp " << exp << std::endl;
				std::cout << "act " << act << std::endl;
				throw RTE_LOC;
			}
			if (t != tAct)
				throw RTE_LOC;
		}
	}
#else
	throw UnitTestSkipped("ENABLE_TERNARY_DPF not defined.");
#endif
}
void TritDpf_Proto_Test(const oc::CLP& cmd)
{
	TernaryDpf_Proto_Test_<block, CoeffCtxGF2>(cmd);
	TernaryDpf_Proto_Test_<u8, CoeffCtxGF2>(cmd);
}


