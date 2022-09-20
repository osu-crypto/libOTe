#pragma once
// © 2016 Peter Rindal.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "libOTe/config.h"
#ifdef ENABLE_BITPOLYMUL


#include <stdint.h>
#include <cryptoTools/Common/Defines.h>
#include <vector>
//#include <boost/align/aligned_allocator.hpp>
#include "bitpolymul/bitpolymul.h"
#include <stdlib.h>


namespace osuCrypto
{


    template <typename T, std::size_t N = 16>
    class AlignmentAllocator {
    public:
        typedef T value_type;
        typedef std::size_t size_type;
        typedef std::ptrdiff_t difference_type;

        typedef T* pointer;
        typedef const T* const_pointer;

        typedef T& reference;
        typedef const T& const_reference;

    public:
        inline AlignmentAllocator() throw () { }

        template <typename T2>
        inline AlignmentAllocator(const AlignmentAllocator<T2, N>&) throw () { }

        inline ~AlignmentAllocator() throw () { }

        inline pointer adress(reference r) {
            return &r;
        }

        inline const_pointer adress(const_reference r) const {
            return &r;
        }

        inline pointer allocate(size_type n) {

            auto size = n * sizeof(value_type);
            auto header = N + sizeof(void*);
            auto base = new char[size + header];
            auto ptr = base + sizeof(void*);
            auto offset = (u64)ptr % N;

            if (offset)
            {
                ptr += N - offset;
            }

            char*& basePtr = *(char**)(ptr - sizeof(void*));
            basePtr = base;

            //std::cout<<
            //    "b " << std::hex << (u64)base <<
            //    "p " << std::hex << (u64)ptr <<
            //    "bp " << std::hex << (u64)&basePtr
            //    << std::endl << std::dec;

            return (pointer)ptr;
        }

        inline void deallocate(pointer ptr, size_type) {
            char*& basePtr = *(char**)((char*)ptr - sizeof(void*));

            //std::cout << "del \n" <<
            //    "b " << std::hex << (u64)basePtr <<
            //    "p " << std::hex << (u64)ptr <<
            //    "bp " << std::hex << (u64)&basePtr
            //    << std::endl << std::dec;


            delete[](basePtr);
        }

        inline void construct(pointer p, const value_type& wert) {
            new (p) value_type(wert);
        }

        inline void destroy(pointer p) {
            p->~value_type();
        }

        inline size_type max_size() const throw () {
            return size_type(-1) / sizeof(value_type);
        }

        template <typename T2>
        struct rebind {
            typedef AlignmentAllocator<T2, N> other;
        };

        bool operator!=(const AlignmentAllocator<T, N>& other) const {
            return !(*this == other);
        }

        // Returns true if and only if storage allocated from *this
        // can be deallocated from other, and vice versa.
        // Always returns true for stateless allocators.
        bool operator==(const AlignmentAllocator<T, N>& other) const {
            return true;
        }
    };


    template <typename T>
    using aligned_vector = std::vector<T, AlignmentAllocator<T, 32>>;




    void bitpolymul(uint64_t* c, const uint64_t* a, const uint64_t* b, uint64_t n_64);

    class FFTPoly
    {
    public:

        FFTPoly() = default;
        FFTPoly(const FFTPoly&) = default;
        FFTPoly(FFTPoly&&) = default;

        FFTPoly(span<const u64> data)
        {
            encode(data);
        }

        u64 mN = 0, mNPow2 = 0;
        aligned_vector<u64> mPoly;

        void resize(u64 n);

        void encode(span<const u64> data);


        void mult(const FFTPoly& a, const FFTPoly& b);
        void multEq(const FFTPoly& b);

        void add(const FFTPoly& a, const FFTPoly& b);
        void addEq(const FFTPoly& b);


        struct DecodeCache
        {
            aligned_vector<u64> mTemp, mTemp2;
        };

        void decode(span<u64> dest, bool destructive = true);
        void decode(span<u64> dest, DecodeCache& cache, bool destructive);

    };

    inline std::ostream& operator<<(std::ostream& o, const FFTPoly& p)
    {
        //o << toStr(p.mPoly);
        o << "[" << p.mPoly.size() << "][";
        for (const auto& v : p.mPoly)
        {
            o << v << ", ";
        }
        o << "]";
        return o;
    }
}

#endif
