#pragma once

#include "libOTe/Base/SimplestOT.h"
#include "libOTe/Base/McRosRoyTwist.h"
#include "libOTe/Base/McRosRoy.h"
#include "libOTe/Tools/Popf/EKEPopf.h"
#include "libOTe/Tools/Popf/MRPopf.h"
#include "libOTe/Tools/Popf/FeistelPopf.h"
#include "libOTe/Tools/Popf/FeistelMulPopf.h"
#include "libOTe/Tools/Popf/FeistelRistPopf.h"
#include "libOTe/Tools/Popf/FeistelMulRistPopf.h"
#include "libOTe/Base/MasnyRindal.h"
#include "libOTe/Base/MasnyRindalKyber.h"

#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/CLP.h"

namespace osuCrypto
{
    bool baseOT_examples(const CLP& clp);
}
