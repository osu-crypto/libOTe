#include "Cmp_Tests.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitIterator.h"
#include "cryptoTools/Common/TestCollection.h"
namespace osuCrypto
{
	template<typename T>
	std::string bits(T v)
	{
		u64 bits = sizeof(T) * 8;

		std::string ret;
		for (u64 i = bits - 1; i < bits; --i)
		{
			ret += std::to_string((v >> i) & 1);
		}
		return ret;
	}

	void Cmp_greaterThan_test(const oc::CLP& cmd)
	{
		u64 n = 8;
		using T = u8;
		u64 trials = cmd.getOr("t", 100);
		PRNG prng(block(3423345222341334, 2394871239472938));
		for (u64 t = 0; t < trials; ++t)
		{


			//std::array<T, 2> as = prng.get(), bs = prng.get();
			//T a = as[0] + as[1];
			//T b = bs[0] + bs[1];

			//// overflow
			//if (u64(a) - u64(b) != (a - b))
			//	continue;



			//std::array<T, 2> cs;
			//cs[0] = as[0] - bs[0];
			//cs[1] = as[1] - bs[1];

			//T A = cs[0];
			//T B = 1 << (n - 1) - 1 - cs[1];
			T A = prng.get();
			T B = prng.get();

			std::cout << "   a " << bits(A) << " " << u64(A) << std::endl;
			std::cout << "   b " << bits(B) << " " << u64(B) << std::endl;
			T e = A ^ B;
			std::cout << " + e " << bits(e) << std::endl;
			std::cout << "in d ";
			std::vector<u8> d(n);
			for (u64 i = n-1; i < n; --i)
			{
				d[i] = (e >> i) & 1;
				std::cout << int(d[i]);
			}
			std::cout << std::endl;

			std::cout << "  s' ";
			std::vector<u8> sp(n);
			for (u64 i = n - 1; i < n; --i)
			{
				if (i!= n-1)
					sp[i] += sp[i + 1];
				sp[i] += d[i];
				std::cout << int(sp[i]);
			}
			std::cout << std::endl;

			std::cout << "  s  ";
			std::vector<u8> s(n);
			for (u64 i = n - 1; i < n; --i)
			{
				s[i] = sp[i] - 2 * d[i] + 1;
				std::cout << int(s[i]);
			}
			std::cout << std::endl;


			std::cout << "   z ";
			std::vector<u8> z(n);
			for (u64 i = n - 1; i < n; --i)
			{
				z[i] = s[i] == 0 ? 1 : 0;
				std::cout << int(z[i]);
			}
			std::cout << std::endl;


			u8 y = 0;
			std::cout << "   z ";
			std::vector<u8> AA(n);
			for (u64 i = n - 1; i < n; --i)
			{
				AA[i] = z[i] & ((A >> i) &1);
				std::cout << int(AA[i]);

				y ^= AA[i];
			}
			std::cout << std::endl;

			std::cout << "   y " << int(y) << std::endl;
			std::cout << "   A > B " << (A > B) << std::endl;
			std::cout << std::endl;
			if (bool(y) != (A > B))
				throw UnitTestFail();

			//std::array<T, 2> ds;
			//ds[0] = A;
			//ds[1] = B;

			//std::vector< std::array<T, 2>> es(n);

			//for (u64 i = 0; i < n; ++i)
			//{
			//	auto d0i = *BitIterator((u8*)&ds[0], i);
			//	auto d1i = *BitIterator((u8*)&ds[1], i);

			//	es[i][0] = prng.get<T>() % n;
			//	es[i][1] = ((d0i ^ d1i) - es[i][0] + n) % n;

			//	if ((es[i][0] + es[i][1]) % n != (d0i ^ d1i))
			//		throw UnitTestFail();
			//}


			//std::vector< std::array<T, 2>> ss(n);
			//std::array<T, 2> zs;
			////std::array<u8, 2> ys = { 0,0 };
			//u8 y = 0;
			//for (u64 i = 0; i < n; ++i)
			//{
			//	std::array<T, 2> si;
			//	si[0] = -2 * es[i][0];
			//	si[1] = 1 - 2 * es[i][1];
			//	for (u64 j = i; j < n; ++j)
			//	{
			//		si[0] += es[i][0];
			//		si[1] += es[i][1];
			//	}

			//	ss[i] = si;

			//	auto zi = ((si[0] + si[1]) % n) == 0;
			//	//*BitIterator((u8*)&zs[0], i) = prng.getBit();
			//	//*BitIterator((u8*)&zs[0], i) = *BitIterator((u8*)&zs[0], i) ^ zi;

			//	y ^= (zi & (A >> i)) & 1;
			//}

			//if (bool(y) != (A > B))
			//	throw UnitTestFail();
		}

	}
}