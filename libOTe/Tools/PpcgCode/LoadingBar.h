#pragma once
#include "cryptoTools/Common/Defines.h"

#include <iostream>
#include <sstream>
#include <future>
#include <atomic>
#include <mutex>
#include <thread>
#include <chrono>
#include <string>
#include <vector>


namespace osuCrypto
{

	struct LoadingBar
	{
		u64 mWidth = 25;
		std::atomic<u64> mProgress;
		std::promise<void> mProm;
		u64 mTotal;
		std::string mMessage;
		//std::chrono::time_point<std::chrono::system_clock> mStart;
		std::mutex mLock;
		bool mPrint = true;
		bool done = false;
		void cancel()
		{
			if (!done)
				mProm.set_value();
			done = true;
		}

		void start(u64 total, std::string message)
		{
			mProgress = 0;
			mTotal = total;
			mMessage = message;
			done = false;
			//mStart = std::chrono::system_clock::now();
			mProm = std::promise<void>();
		}

		void tick(u64 delta = 1)
		{
			auto res = mProgress.fetch_add(delta, std::memory_order_relaxed);
			if (res + delta == mTotal)
			{
				done = true;
				mProm.set_value();
			}
		}

		void print()
		{
			double avgRate = -1;
			u64 lastCount = 0;
			u64 leng = 0;
			auto f = mProm.get_future();
			std::chrono::milliseconds step(1000);
			std::chrono::system_clock::time_point last = std::chrono::system_clock::now();
			f.wait_for(step);// first sleep in case its fast...
			while (f.wait_for(step) == std::future_status::timeout)
			{
				auto now = std::chrono::system_clock::now();
				auto count = mProgress.load(std::memory_order_relaxed);

				auto newCount = count - lastCount;

				if (newCount == 0)
					continue;

				// seconds since start
				auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last).count() / 1000.0;


				// ticks per sec
				auto rate = double(newCount) / elapsed;
				avgRate = avgRate < 0 ? rate : avgRate * 0.9 + rate * 0.1;

				auto rem = mTotal - count;

				// time remaining in sec
				i64 eta = rem / avgRate;

				auto sec = eta % 60;
				auto min = (eta / 60) % 60;
				auto hour = eta / 3600;

				u64 numBars = double(count) * mWidth / mTotal;
				std::stringstream ss;
				ss << "\r" << mMessage << " [" << std::string(numBars, '|') << std::string(mWidth - numBars, ' ') << "] "
					<< count << "/" << mTotal << ", rate: " << u64(avgRate) << " ticks/sec,  ETA: ";

				if (hour)
					ss << hour << "h " << min << "m " << sec << "s";
				else if (min)
					ss << min << "m " << sec << "s";
				else
					ss << sec << "s";

				auto str = ss.str();
				std::cout << str << std::string(std::max<i64>(leng - str.size(), 0), ' ') << std::flush;
				leng = std::max(leng, str.size());


				lastCount = count;
				last = now;
			}

			std::cout << std::string(leng, ' ') << "\r" << std::flush;
		}

	};
	static LoadingBar loadBar;
}