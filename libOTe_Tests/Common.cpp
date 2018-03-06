//#include "stdafx.h"
#include "Common.h"
#include <cryptoTools/Common/Log.h>

#include <fstream>
#include <cassert> 

using namespace osuCrypto;

namespace tests_libOTe
{
    static std::fstream* file = nullptr;
    std::string SolutionDir = "../../";

    void InitDebugPrinting(std::string filePath)
    {
        std::cout << "changing sink" << std::endl;

        if (file == nullptr)
        {
            file = new std::fstream;
        }
        else
        {
            file->close();
        }

        file->open(filePath, std::ios::trunc | std::ofstream::out);

        if (!file->is_open())
            throw std::runtime_error("failed to open file: " + filePath);

        //time_t now = time(0);

        std::cout.rdbuf(file->rdbuf());
        std::cerr.rdbuf(file->rdbuf());
        //Log::SetSink(*file); 
    }

}