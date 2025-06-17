
#include "BlockDiagonal.h"
#include <cassert>   // For assert
#include <iostream>  // For std::cerr
#include <stdexcept> // For std::runtime_error
#include "cryptoTools/Common/Defines.h"

namespace osuCrypto {

/*
    void initialize_matrix_meta(GeneratorMatrixMeta& matrix_meta, int sigma, int e, int t) {
        matrix_meta.t = t;
        matrix_meta.block_num_rows = sigma * e;
        matrix_meta.block_num_cols = sigma;

        // TODO: We don't need to store these vectors at all
        matrix_meta.row_indices.resize(t);
        matrix_meta.col_indices.resize(t);

        for (int i = 0; i < t; ++i) {
            matrix_meta.row_indices[i] = i * sigma * e;
            matrix_meta.col_indices[i] = i * sigma;
        }

    }
*/


} // namespace osuCrypto