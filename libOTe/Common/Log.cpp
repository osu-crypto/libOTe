#include "Log.h"
#include <iostream>
#include "Common/Defines.h"
#ifdef _MSC_VER
#include <windows.h>
#endif
#include <boost/thread/tss.hpp>

//
//void CleanupThreadInfo(void*)
//{
//    if (0);
//}
//
//static boost::thread_specific_ptr< void*> precision(CleanupThreadInfo);
//static void* GetPrecision()
//{
//    if (!precision.get())
//    { 
//    }
//    return precision.get();
//}
//
//

namespace osuCrypto
{




    LoggerStream Log::out(std::cout);
    
    void Log::SetSink(std::ostream& out)
    {
        std::cout << "SetSink___" << std::endl;

        Log::out.mSink = &out;
    }


    //void Log::EnableTag(const Tag& tag)
    //{
    //    //(*(u32*)(&out.mEnabledTags)) |= (u32)tag;
    //}

    //void Log::DisableTag(const Tag& tag)
    //{
    //    //(*(u32*)(&out.mEnabledTags)) &= ~(u32)tag;
    //}


    void Log::setThreadName(const std::string name)
    {
        setThreadName(name.c_str());
    }
    void Log::setThreadName(const char* name)
    {
#ifndef NDEBUG 
#ifdef _MSC_VER
    const DWORD MS_VC_EXCEPTION = 0x406D1388;

#pragma pack(push,8)
        typedef struct tagTHREADNAME_INFO
        {
            DWORD dwType; // Must be 0x1000.
            LPCSTR szName; // Pointer to name (in user addr space).
            DWORD dwThreadID; // Thread ID (-1=caller thread).
            DWORD dwFlags; // Reserved for future use, must be zero.
        } THREADNAME_INFO;
#pragma pack(pop)


        THREADNAME_INFO info;
        info.dwType = 0x1000;
        info.szName = name;
        info.dwThreadID = -1;
        info.dwFlags = 0;

        __try
        {
            RaiseException(MS_VC_EXCEPTION, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR*)&info);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
#endif
#endif
    }

    const Log::Color Log::ColorDefault([]() ->Log::Color {
#ifdef _MSC_VER
        CONSOLE_SCREEN_BUFFER_INFO   csbi;
        HANDLE m_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        GetConsoleScreenBufferInfo(m_hConsole, &csbi);

        return (Log::Color)(csbi.wAttributes & 255);
#else 
        return Log::Color::White;
#endif

    }());

#ifdef _MSC_VER
    const HANDLE Log::__m_hConsole(GetStdHandle(STD_OUTPUT_HANDLE));
#endif

    LoggerStream& LoggerStream::operator<<(const Log::Color tag)
    {
#ifdef _MSC_VER
        SetConsoleTextAttribute(Log::__m_hConsole, (WORD)tag | (240 & (WORD)Log::ColorDefault) );
#endif
        return *this;
    }
}
