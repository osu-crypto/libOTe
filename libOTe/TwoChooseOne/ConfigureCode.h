#pragma once
#include "libOTe/config.h"
#include "cryptoTools/Common/Defines.h"


namespace osuCrypto
{

	enum class MultType
	{
		// https://eprint.iacr.org/2019/1159.pdf
		QuasiCyclic = 1,
#ifdef ENABLE_INSECURE_SILVER
		// https://eprint.iacr.org/2021/1150, see https://eprint.iacr.org/2023/882 for attack.
		slv5 = 2,
		slv11 = 3,
#endif
		// https://eprint.iacr.org/2022/1014
		ExAcc7 = 4, // fast
		ExAcc11 = 5,// fast but more conservative
		ExAcc21 = 6,
		ExAcc40 = 7, // conservative

		// https://eprint.iacr.org/2023/882
		ExConv7x24 = 8, //fastest
		ExConv21x24 = 9 // conservative.
	};

	inline std::ostream& operator<<(std::ostream& o, MultType m)
	{
		switch (m)
		{
		case osuCrypto::MultType::QuasiCyclic:
			o << "QuasiCyclic";
			break;
#ifdef ENABLE_INSECURE_SILVER
		case osuCrypto::MultType::slv5:
			o << "slv5";
			break;
		case osuCrypto::MultType::slv11:
			o << "slv11";
			break;
#endif
		case osuCrypto::MultType::ExAcc7:
			o << "ExAcc7";
			break;
		case osuCrypto::MultType::ExAcc11:
			o << "ExAcc11";
			break;
		case osuCrypto::MultType::ExAcc21:
			o << "ExAcc21";
			break;
		case osuCrypto::MultType::ExAcc40:
			o << "ExAcc40";
			break;
		case osuCrypto::MultType::ExConv21x24:
			o << "ExConv21x24";
			break;
		case osuCrypto::MultType::ExConv7x24:
			o << "ExConv7x24";
			break;
		default:
			throw RTE_LOC;
			break;
		}

		return o;
	}

	constexpr MultType DefaultMultType = MultType::ExConv7x24;

    // We get e^{-2td} security against linear attacks, 
    // with noise weigh t and minDist d. 
    // For regular we can be slightly more accurate with
    //    (1 − 2d)^t
    // which implies a bit security level of
    // k = -t * log2(1 - 2d)
    // t = -k / log2(1 - 2d)
    u64 getRegNoiseWeight(double minDistRatio, u64 secParam);


    class EACode;

	void EAConfigure(
		u64 numOTs, u64 secParam,
		MultType mMultType,
		u64& mRequestedNumOTs,
		u64& mNumPartitions,
		u64& mSizePer,
		u64& mN2,
		u64& mN,
		EACode& mEncoder
	);


	class ExConvCode;
	void ExConvConfigure(
		u64 numOTs, u64 secParam,
		MultType mMultType,
		u64& mRequestedNumOTs,
		u64& mNumPartitions,
		u64& mSizePer,
		u64& mN2,
		u64& mN,
		ExConvCode& mEncoder
	);

#ifdef ENABLE_INSECURE_SILVER
	struct SilverEncoder;
	void SilverConfigure(
		u64 numOTs, u64 secParam,
		MultType mMultType,
		u64& mRequestedNumOTs,
		u64& mNumPartitions,
		u64& mSizePer,
		u64& mN2,
		u64& mN,
		u64& gap,
		SilverEncoder& mEncoder);
#endif

	void QuasiCyclicConfigure(
		u64 numOTs, u64 secParam,
		u64 scaler,
		MultType mMultType,
		u64& mRequestedNumOTs,
		u64& mNumPartitions,
		u64& mSizePer,
		u64& mN2,
		u64& mN,
		u64& mP,
		u64& mScaler);
}