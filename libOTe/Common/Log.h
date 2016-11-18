#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <string>
#include <vector>
#include "Common/Defines.h"
#include <list>
#include <atomic>
#include <mutex>

#ifdef _MSC_VER
# include <windows.h> 
#endif

#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

#ifdef GetMessage
#undef GetMessage
#endif

namespace osuCrypto
{

    //#define LOGGER_DEBUG(x) Log::out x

    class LoggerStream;

    //void Cleanup_Miracl(Miracl* miracl)
    //{
    //    if (miracl)
    //        delete miracl;
    //}

    //static boost::thread_specific_ptr<std::stringstream> line;
    //static std::stringstream& getLine()
    //{
    //    if (!line.get())
    //    {
    //        line.reset(new std::stringstream());
    //    }
    //    return *line.get();
    //}

    //class LoggerThreadInfo
    //{
    //    u64 mThreadID;
    //    std::string mName;
    //    std::list<std::pair<u32, std::stringstream>>* mBuffer;
    //};

    class Log
    {
    public:
#ifdef _MSC_VER
        static const HANDLE __m_hConsole;
#endif

        enum class Color {
            LightGreen = 2,
            LightGrey = 3,
            LightRed = 4,
            OffWhite1 = 5,
            OffWhite2 = 6,
            Grey = 8,
            Green = 10,
            Blue = 11,
            Red = 12,
            Pink = 13,
            Yellow = 14,
            White = 15
        };

        const static Color ColorDefault;


        enum Modifier
        {
            endl,
            lock,
            unlock
        };

        static LoggerStream out;

        static void SetSink(std::ostream& out);

        //static LoggerStream& stream()
        //{
        //    return out;
        //}

        //static std::unique_lock<std::mutex>&& getPrintLock()
        //{
        //    return std::move(std::unique_lock<std::mutex>(mMtx));
        //} 
        static void setThreadName(const std::string name);
        static void setThreadName(const char* name);


    private:

    };




    class LoggerStream
    {
    public:
        friend class Log;
        std::ostream* mSink; 

        std::mutex mMtx;

        LoggerStream(std::ostream& stream)
            :mSink(&stream)
        {
        }
        ~LoggerStream()
        {
            if (mSink)
                mSink->flush();
        }

        template<typename T>
        LoggerStream& operator<<(const T& in)
        {
            *mSink << in;
            return *this;
        }
        LoggerStream& operator<<(const Log::Modifier in)
        {
            switch (in)
            {
            case Log::Modifier::endl:
                *mSink << std::endl;
                break;
            case Log::Modifier::lock:
                mMtx.lock();
                break;
            case Log::Modifier::unlock:
                mMtx.unlock();
                break;
            default:
                break;
            }
            return *this;
        }

        LoggerStream& operator<<(const Log::Color tag);
    };



}
