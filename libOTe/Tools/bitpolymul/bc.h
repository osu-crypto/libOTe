#pragma once
/*
Copyright (C) 2017 Ming-Shing Chen

This file is part of BitPolyMul.

BitPolyMul is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

BitPolyMul is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with BitPolyMul.  If not, see <http://www.gnu.org/licenses/>.
*/


#include "libOTe/config.h"
#ifdef ENABLE_SILENTOT

#include <stdint.h>
#include "bpmDefines.h"

namespace bpm {


    typedef uint64_t bc_sto_t;
    void bc_to_lch_256_30_12(__m256i* poly, int logn);
    void bc_to_lch_256_19_17(__m256i* poly, int logn);
    void bc_to_lch_256_16(__m256i* poly, int logn);
    void bc_to_mono_256_16(__m256i* poly, int logn);
    void bc_to_mono_256_19_17(__m256i* poly, int logn);
    void bc_to_mono_256_30_20(__m256i* poly, int logn);

    void bc_to_lch_2_unit256(bc_sto_t* poly, u64 n_terms);

    void bc_to_mono_2_unit256(bc_sto_t* poly, u64 n_terms);

}


#endif
