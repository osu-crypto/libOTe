#include "frontend/ExampleLogVole.h"

#include <exception>
#include <iostream>

int main(int argc, char** argv)
{
    try
    {
        const osuCrypto::CLP cmd(argc, argv);
        if (osuCrypto::LogVole_Examples(cmd)) return 0;
        std::cerr << "The launcher requires -logvole.\n";
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
    }
    return 1;
}
