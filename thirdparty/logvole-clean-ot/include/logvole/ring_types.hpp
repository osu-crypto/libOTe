#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace logvole
{
    struct ring_params
    {
        std::uint32_t poly_modulus_degree = 0;
        std::vector<int> coeff_modulus_bits{};

        bool operator==(const ring_params &other) const
        {
            return poly_modulus_degree == other.poly_modulus_degree && coeff_modulus_bits == other.coeff_modulus_bits;
        }

        bool operator!=(const ring_params &other) const
        {
            return !(*this == other);
        }
    };

    struct ring_rns_poly
    {
        std::vector<std::uint64_t> coeffs{};
    };

    struct ring_tensor
    {
        std::uint32_t rows = 0;
        std::uint32_t cols = 0;
        std::vector<ring_rns_poly> polys{};
    };

    inline std::size_t ring_poly_coeff_count(const ring_params &params)
    {
        return static_cast<std::size_t>(params.poly_modulus_degree) * params.coeff_modulus_bits.size();
    }

    inline std::size_t ring_tensor_size(const ring_tensor &tensor)
    {
        return static_cast<std::size_t>(tensor.rows) * tensor.cols;
    }

    inline std::size_t ring_tensor_index(const ring_tensor &tensor, std::uint32_t row, std::uint32_t col)
    {
        return static_cast<std::size_t>(row) * tensor.cols + col;
    }

} // namespace logvole
