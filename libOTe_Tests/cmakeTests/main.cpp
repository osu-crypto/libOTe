

#include "libOTe/Tools/Tools.h"
#include "libOTe/config.h"

#ifdef ENABLE_SPIN
#include <libOTe/Tools/Spin/SpinOt.h>
#include <vector>

static int spinConsumerCheck() {
    if(!spin::capabilities().avx2) return 0;
    const auto spec=osuCrypto::detail::spinProfile(4096);
    if(spec.message_size!=8192) return 1;
    const auto cfg=osuCrypto::SpinConfigure(128,4096,osuCrypto::SdNoiseDistribution::Regular);
    if(cfg.mNumPartitions!=128 || cfg.mNoiseVectorSize!=16384) return 2;
    // Exercise the public installed-package interface, including the new
    // refresh API and the generic workspace's live view of each map.
    for(auto mode:{spin::SetupMode::Full,spin::SetupMode::BankedHeuristic}) {
        osuCrypto::SpinCode code(spec,{}, {mode});
        auto workspace=code.make_workspace<osuCrypto::block>();
        auto generic=code.make_workspace<osuCrypto::u64>();
        std::vector<osuCrypto::block> values(code.codeSize());
        std::vector<osuCrypto::u64> words(code.codeSize());
        for(osuCrypto::u64 round=0;round<3;++round) {
            code.setCodeSeed(osuCrypto::block(29+round,17+round));
            for(std::size_t i=0;i<words.size();++i) {
                words[i]=(osuCrypto::u64(i)+1)*0x9e3779b97f4a7c15ULL;
                values[i]=osuCrypto::block(0,words[i]);
            }
            code.transpose_inplace<osuCrypto::block>(values,workspace);
            code.transpose_inplace<osuCrypto::u64>(words,generic);
            for(std::size_t i=0;i<words.size();++i)
                if(values[i]!=osuCrypto::block(0,words[i])) return 3;
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
