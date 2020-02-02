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


    void encode_128_half_input_zero(uint64_t* rfx, const uint64_t* fx, u64 n_fx_128b);

    void decode_128(uint64_t* rfx, const uint64_t* fx, u64 n_fx_128b);

    void encode_64_half_input_zero(uint64_t* rfx, const uint64_t* fx, u64 n_fx);

    void decode_64(uint64_t* rfx, const uint64_t* fx, u64 n_fx);


}



#endif
