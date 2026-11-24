

#include "libOTe/Tools/Tools.h"
#include "libOTe/config.h"

#ifdef ENABLE_SPIN
#include <libOTe/Tools/Spin/SpinCode.h>
#include <vector>

// Installed-package check of the SPIN interface on any CPU: sizes, noise
// configuration, and agreement of the block and choice-byte transposes
// (choice byte i equals bit 0 of block i) across reseeds in both setup modes.
static int spinConsumerCheck() {
    using namespace osuCrypto;
    if(SpinCode::messageSize(4096)!=8192) return 1;
    const auto cfg=SpinConfigure(128,4096,SdNoiseDistribution::Regular);
    if(cfg.mNumPartitions!=128 || cfg.mNoiseVectorSize!=16384) return 2;
    for(auto noise:{SdNoiseDistribution::Regular,SdNoiseDistribution::Stationary}) {
        std::optional<SpinCode> code;
        for(u64 round=0;round<3;++round) {
            SpinCode::prepare(code,4096,block(29+round,17+round),noise);
            std::vector<block> values(code->codeSize());
            std::vector<u8> choices(code->codeSize());
            for(std::size_t i=0;i<values.size();++i) {
                const u64 w=(u64(i)+1)*0x9e3779b97f4a7c15ULL;
                values[i]=block(0,w);
                choices[i]=u8(w&1);
            }
            code->transpose(values);
            code->transpose(choices);
            for(std::size_t i=0;i<code->messageSize();++i)
                if(choices[i]!=(values[i].get<u64>(0)&1)) return 3;
        }
    }
    return 0;
}
#endif

int main()
{
	using namespace oc;
	MatrixView<u8> in, out;
	// call a function that requires linking...
	transpose(in , out);
#ifdef ENABLE_SPIN
    return spinConsumerCheck();
#endif
	return 0;
}
