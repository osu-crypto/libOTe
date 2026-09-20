#include <libOTe/Tools/Spin/SpinOt.h>
#include <vector>

int main() {
    if(!spin::capabilities().avx2) return 77;
    const auto spec=osuCrypto::detail::spinProfile(4096);
    if(spec.message_size!=8192) return 1;
    const auto cfg=osuCrypto::SpinConfigure(128,4096,osuCrypto::SdNoiseDistribution::Regular);
    if(cfg.mNumPartitions!=128 || cfg.mNoiseVectorSize!=16384) return 2;
    osuCrypto::SpinCode code(spec);
    auto workspace=code.make_workspace<osuCrypto::block>();
    auto generic=code.make_workspace<osuCrypto::u64>();
    std::vector<osuCrypto::block> values(code.codeSize());
    std::vector<osuCrypto::u64> words(code.codeSize());
    for(std::size_t i=0;i<words.size();++i) {
        words[i]=(osuCrypto::u64(i)+1)*0x9e3779b97f4a7c15ULL;
        values[i]=osuCrypto::block(0,words[i]);
    }
    code.transpose_inplace<osuCrypto::block>(values,workspace);
    code.transpose_inplace<osuCrypto::u64>(words,generic);
    for(std::size_t i=0;i<words.size();++i)
        if(values[i]!=osuCrypto::block(0,words[i])) return 3;
}
