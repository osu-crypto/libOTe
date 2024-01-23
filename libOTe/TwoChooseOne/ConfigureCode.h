#pragma once
#include "libOTe/config.h"
#include "cryptoTools/Common/Defines.h"


namespace osuCrypto
{

	enum class MultType
	{
		// https://eprint.iacr.org/2019/1159.pdf
		QuasiCyclic = 1,

		// https://eprint.iacr.org/2022/1014
		ExAcc7 = 4, // fast
		ExAcc11 = 5,// fast but more conservative
		ExAcc21 = 6,
		ExAcc40 = 7, // conservative

		// https://eprint.iacr.org/2023/882
		ExConv7x24 = 8, //fast
		ExConv21x24 = 9, // conservative.

		// experimental
		Tungsten // very fast, based on turbo codes. Unknown min distance. 
	};

	inline std::ostream& operator<<(std::ostream& o, MultType m)
	{
		switch (m)
		{
		case osuCrypto::MultType::QuasiCyclic:
			o << "QuasiCyclic";
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
		case osuCrypto::MultType::Tungsten:
			o << "Tungsten";
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
		u64& mNoiseVecSize,
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
		u64& mNoiseVecSize,
		u64& mN,
		ExConvCode& mEncoder
	);


	void ExConvConfigure(
		double scaler,
		MultType mMultType,
		u64& expanderWeight,
		u64& accumulatorWeight,
		double& minDist
	);

	void QuasiCyclicConfigure(
		u64 numOTs, u64 secParam,
		u64 scaler,
		MultType mMultType,
		u64& mRequestedNumOTs,
		u64& mNumPartitions,
		u64& mSizePer,
		u64& mNoiseVecSize,
		u64& mN,
		u64& mP,
		u64& mScaler);


	inline void QuasiCyclicConfigure(
		double mScaler,
		double& minDist) 
	{ 
		if (mScaler == 2)
			minDist = 0.2; // estimated psuedo min dist
		else 
			throw RTE_LOC; // not impl
	}


	inline void TungstenConfigure(
		double mScaler,
		double& minDist)
	{
		if (mScaler == 2)
			minDist = 0.2; // estimated psuedo min dist
		else
			throw RTE_LOC; // not impl
	}
}