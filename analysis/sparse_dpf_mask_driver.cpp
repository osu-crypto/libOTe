// Focused runner for builds where relinking the complete frontend is expensive.
#include "libOTe_Tests/Dpf_Tests.h"
#include "libOTe_Tests/Waterfall_Tests.h"
#include "libOTe_Tests/RevCuckoo_Tests.h"
#include <iostream>

int main(int argc, char** argv)
{
    osuCrypto::CLP cmd;
    cmd.parse(argc, argv);
    try
    {
        const auto run = [&](const char* name, auto test) {
            std::cout << name << std::flush;
            test(cmd);
            std::cout << " passed\n";
        };
        run("SparseDpf_CorrectionEncoding", SparseDpf_CorrectionEncoding_Test);
        run("SparseDpf_InactiveLevel", SparseDpf_InactiveLevel_Test);
        run("CachedDpf_LeafRekey", CachedDpf_LeafRekey_Test);
        run("DpfTreeHash_Rekey", DpfTreeHash_Rekey_Test);
        if (cmd.isSet("maskOnly")) return 0;
        run("RegularDpf_keyGen", RegularDpf_keyGen_Test);
        run("RegularDpf_Proto", RegularDpf_Proto_Test);
        run("RegularDpf_Puncture", RegularDpf_Puncture_Test);
        run("Dpf_Audit", Dpf_Audit_Test);
        run("RegularDpf_Multiply", RegularDpf_Multiply_Test);
        run("RegularDpf_MultByte", RegularDpf_MultByte_Test);
        run("RegularDpf_MultBit", RegularDpf_MultBit_Test);
        run("RegularDpf_MultSession", RegularDpf_MultSession_Test);
        run("RegularDpf_MultGeneric", RegularDpf_MultGeneric_Test);
        run("SparseDpf_Mtx", SparseDpf_Mtx_Test);
        run("SparseDpf_Vec", SparseDpf_Vec_Test);
        run("SparseDpf_Punct", SparseDpf_Punct_Test);
        run("Waterfall_emptySparseColumn", osuCrypto::Waterfall_emptySparseColumn_Test);
        run("Waterfall_validation", osuCrypto::Waterfall_validation_Test);
        run("Waterfall_dmpfEndToEnd", osuCrypto::Waterfall_dmpfEndToEnd_Test);
        run("RevCuckoo_baseOtSlicing", osuCrypto::RevCuckoo_baseOtSlicing_Test);
        run("RevCuckoo_seededSparseSets", osuCrypto::RevCuckoo_seededSparseSets_Test);
        run("RevCuckoo_iterative", osuCrypto::RevCuckoo_iterative_Test);
        run("RevCuckoo_singlePoint", osuCrypto::RevCuckoo_singlePoint_Test);
        run("RevCuckoo_robustness", osuCrypto::RevCuckoo_robustness_Test);
    }
    catch (const std::exception& error)
    {
        std::cerr << " failed: " << error.what() << '\n';
        return 1;
    }
}
