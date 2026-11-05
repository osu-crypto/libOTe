#pragma once
#include "libOTe/Tools/CpuCapabilities.h"

namespace osuCrypto
{
    // Supplied at proof-owner construction and borrowed by its check helpers.
    struct LogVoleZkOptions
    {
        CpuCapabilities mCpu{};
        bool mCpuPseudoReduce = true;
        bool mCpuVectorGates = true;
        bool mCpuVectorWitness = true;
        bool mCpuVectorMatMul = true;
        bool mDeviceConstants = true;
        bool mGpuPseudoReduce = true;
        bool mDeviceAcceptance = true;
    };
}
