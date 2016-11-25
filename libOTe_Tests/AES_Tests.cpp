//#include "stdafx.h"

#include <thread>
#include <vector>
#include <memory>

#include "Common.h"
#include "Common/Defines.h"
#include "Crypto/AES.h" 
#include "Common/Log.h"

using namespace osuCrypto;

//namespace osuCrypto_tests
//{


    void AES_EncDec_Test()
    {

        block userKey = _mm_set_epi64x(12345678, 1234567);

        AES encKey(userKey);
        AESDec decKey(userKey);

        u64 length = 100;

        std::vector<block> data(length);
        std::vector<block> cyphertext1(length);
        std::vector<block> cyphertext2(length);

        std::vector<block> plaintext(length);

        //std::cout << encKey.mRoundKey[0] << std::endl;

        for (u64 i = 0; i < length; ++i)
        {
            data[i] = _mm_set1_epi64x(i);

            encKey.ecbEncBlock(data[i], cyphertext1[i]);
            decKey.ecbDecBlock(cyphertext1[i], plaintext[i]);


            if (neq(data[i], plaintext[i]))
                throw UnitTestFail();
        }

        //std::cout << encKey.mRoundKey[0] << std::endl;

        encKey.ecbEncBlocks(data.data(), data.size(), cyphertext2.data());


        for (u64 i = 0; i < length; ++i)
        {
            //std::cout << i << " " << cyphertext1[i] << " " << cyphertext2[i] << std::endl;


            if (neq(cyphertext1[i], cyphertext2[i]))
                throw UnitTestFail();
        }

    }


//}