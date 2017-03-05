#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <string>

namespace tests_libOTe
{
    //
    void InitDebugPrinting(std::string file = "../../testout.txt");
    //
    extern std::string SolutionDir;

    class UnitTestFail : public std::exception
    {
        std::string mWhat;
    public:
        explicit UnitTestFail(std::string reason)
            :std::exception(),
            mWhat(reason)
        {}

        explicit UnitTestFail()
            :std::exception(),
            mWhat("UnitTestFailed exception")
        {
        }

        virtual  const char* what() const throw()
        {
            return mWhat.c_str();
        }
    };

}