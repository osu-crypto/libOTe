#pragma once
#include "libOTe/config.h"
#include "cryptoTools/Common/Defines.h"


namespace osuCrypto
{

	enum class MultType
	{
		QuasiCyclic = 1,
		slv5,
		slv11,
		ExAcc7, // fast
		ExAcc11,// fast but more conservative
		ExAcc21,
		ExAcc40, // conservative
		ExConv7x24, //fast
		ExConv21x24 // conservative.
	};

	inline std::ostream& operator<<(std::ostream& o, MultType m)
	{
		switch (m)
		{
		case osuCrypto::MultType::QuasiCyclic:
			o << "QuasiCyclic";
			break;
		case osuCrypto::MultType::slv5:
			o << "slv5";
			break;
		case osuCrypto::MultType::slv11:
			o << "slv11";
			break;
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