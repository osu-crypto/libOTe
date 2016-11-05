//#include "stdafx.h"
#include "Common.h"
#include "Common/Log.h"

#include <fstream>
#include <cassert> 

using namespace osuCrypto;

static std::fstream* file = nullptr;
std::string SolutionDir = "../../";

void InitDebugPrinting(std::string filePath)
{
    Log::out << "changing sink" << Log::endl;

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
        throw UnitTestFail();

    time_t now = time(0);

    std::cout.rdbuf(file->rdbuf());
    std::cerr.rdbuf(file->rdbuf());
    //Log::SetSink(*file); 
}

