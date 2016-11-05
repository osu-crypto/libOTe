#include "Timer.h"
#include <ostream>
#include <string>
#include "Common/Defines.h"
#include "Common/Log.h"
namespace osuCrypto
{
    //const Timer::timeUnit  Timer::mStart(Timer::timeUnit::clock::now());

    const Timer::timeUnit& Timer::setTimePoint(const std::string& msg)
    {
        mTimes.push_back(std::make_pair(timeUnit::clock::now(), msg));

        //Log::out << msg << "     " << std::chrono::duration_cast<std::chrono::milliseconds>(mTimes.back().first - mStart).count() << Log::endl;

        return mTimes.back().first;
        //return mStart;
    }

    void Timer::reset()
    {
        mStart = Timer::timeUnit::clock::now();
        mTimes.clear();
    }

    std::ostream& operator<<(std::ostream& out, const Timer& timer)
    {
        if (timer.mTimes.size())
        {
            auto iter = timer.mTimes.begin();
            out << iter->second;

            u64 tabs = std::min((u64)4, (u64)4 - (iter->second.size() / 8));

            for (u64 i = 0; i < tabs; ++i)
                out << "\t";
            
            out << "  " << std::chrono::duration_cast<std::chrono::milliseconds>(iter->first - timer.mStart).count() << std::endl;

            auto prev = iter;
            while (++iter != timer.mTimes.end())
            {
                out << iter->second;
                
                tabs = std::min((u64)4,  (u64)4 - (iter->second.size() / 8));

                for (u64 i = 0; i < tabs ; ++i)
                    out << "\t";

                out << "  " << std::chrono::duration_cast<std::chrono::milliseconds>(iter->first - timer.mStart).count() <<
                    "  "<< std::chrono::duration_cast<std::chrono::microseconds>(iter->first - prev->first).count()  << std::endl;

                ++prev;
            }
        }
        return out;
    }
}