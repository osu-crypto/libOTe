#pragma once
#include <vector>
#include "cryptoTools/Common/Defines.h"

namespace osuCrypto
{

  //  /**
  //   * @brief Base class for all linear error correcting codes but 
  //   * used to compress, i.e. compute x = G * c instead of c = x * G.
  //   *
  //   * This abstract class defines the interface for codes that map
  //   * between message and codeword spaces, providing a consistent way
  //   * to encode and decode data.
  //   *
  //   * @tparam T The type of elements in the code (e.g., block, u8)
  //   * @tparam CoeffCtx The context providing arithmetic operations for type T
  //   */
  //  template <typename T>
  //  class BaseCode {
  //  public:

  //      u64 mK = 0;
  //      u64 mN = 0;

		//BaseCode() = default;
		//BaseCode(u64 k, u64 n) : mK(k), mN(n) {}
		//BaseCode(const BaseCode&) = default;
		//BaseCode(BaseCode&&) = default;
		//BaseCode& operator=(const BaseCode&) = default;
		//BaseCode& operator=(BaseCode&&) = default;


  //      virtual ~BaseCode() = default;

  //      /**
  //       * @brief Indicates if the code operates in-place
  //       *
  //       * If true, the input to dualEncode will be ignored and must be size 0,
  //       * with the input data expected to be in the output parameter.
  //       *
  //       * @return true if the code operates in-place
  //       * @return false if separate input and output are required
  //       */
  //      virtual bool inplace() const = 0;

  //      /**
  //       * @brief Apply the code to transform between message and codeword spaces
  //       *
  //       * @param input The input data (can be message or codeword depending on direction)
  //       * @param output The output data (can be codeword or message depending on direction)
  //       */
  //      virtual void dualEncode(span<T> input, span<T> output, CoeffCtx ctx) = 0;

  //  };

}