#include "Simulator.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/CLP.h"
#include <iomanip>
#include <thread>
#include <atomic>
#include <fstream>
#include <vector>

#include "cryptoTools/Common/CuckooIndex.h"

namespace osuCrypto
{

	class PartitionedCuckoo
	{
	public:
		PartitionedCuckoo();
		~PartitionedCuckoo();

		struct Bin
		{
			Bin() :mVal(-1) {}
			Bin(u64 idx, u64 hashIdx) : mVal(idx | (hashIdx << 56)) {}

			bool isEmpty() const;
			u64 idx() const;
			u64 hashIdx() const;

			void swap(u64& idx, u64& hashIdx);
			Bin(const Bin& b) : mVal(b.mVal) {}
			Bin(Bin&& b) : mVal(b.mVal) {}
			u64 mVal;
		};
		struct Workspace
		{
			Workspace(u64 n, u64 h)
				: curAddrs(n)
				, curHashIdxs(n)
				, oldVals(n)
				, findVal(n, h)
			{
			}

			std::vector<u64>
				curAddrs,
				curHashIdxs,
				oldVals;

			Matrix<u64>   findVal;
		};



		u64 mTotalTries;

		bool operator==(const PartitionedCuckoo& cmp)const;
		bool operator!=(const PartitionedCuckoo& cmp)const;

		u64 mN = 0;
		u64 mNumHashes = 0;
		u64 mPartitionSize = 0;

		void print() const;
		void init();

		void insert(span<block> items, block hashingSeed)
		{
			std::vector<block> hashs(items.size());
			std::vector<u64> idxs(items.size());
			AES hasher(hashingSeed);

			for (u64 i = 0; i < u64(items.size()); i += u64(hashs.size()))
			{
				auto min = std::min<u64>(items.size() - i, hashs.size());

				hasher.ecbEncBlocks(items.data() + i, min, hashs.data());

				for (u64 j = 0, jj = i; j < min; ++j, ++jj)
				{
					idxs[j] = jj;
					hashs[j] = hashs[j] ^ items[jj];
				}

				insert(idxs, hashs);
			}
		}

		void insert(span<u64> itemIdxs, span<block> hashs)
		{
			Workspace ws(itemIdxs.size(), mNumHashes);
			//std::vector<block> bb(mNumHashes);
			Matrix<u64> hh(hashs.size(), mNumHashes);

			if (1ull << log2ceil(mPartitionSize) != mPartitionSize)
				throw RTE_LOC;
			u64 mask = mPartitionSize - 1;
			AES aes(CCBlock);
			aes.hashBlocks(hashs, hashs);
			auto bytesPer = divCeil(log2ceil(mPartitionSize), 8);

			for (i64 i = 0; i < i64(hashs.size()); ++i)
			{
				auto bytes = hashs[i].get<u8>();
				span<u8> s(bytes);
				for (u64 j = 0; j < mNumHashes; ++j)
				{
					copyBytesMin(hh(i,j), s.subspan(j * bytesPer, bytesPer));
					hh(i, j) &= mask;
					hh(i, j) += (j * mPartitionSize);
				}
			}

			insertBatch(itemIdxs, hh, ws);
		}
		void insertBatch(span<u64> itemIdxs, MatrixView<u64> hashs, Workspace& workspace);

		u64 findBatch(MatrixView<u64> hashes,
			span<u64> idxs,
			Workspace& wordkspace);

		u64 stashUtilization();

		std::vector<u64> mHashes;
		MatrixView<u64> mHashesView;

		std::vector<Bin> mBins;
		std::vector<Bin> mStash;
	};

	PartitionedCuckoo::PartitionedCuckoo()
		:mTotalTries(0)
	{
	}

	PartitionedCuckoo::~PartitionedCuckoo()
	{

		mHashes = std::vector<u64>();
		mHashesView = MatrixView<u64>();

		mBins = std::vector<Bin>();
		mStash = std::vector<Bin>();

	}

	bool PartitionedCuckoo::operator==(const PartitionedCuckoo& cmp) const
	{
		if (mBins.size() != cmp.mBins.size())
			throw std::runtime_error("");

		if (mStash.size() != cmp.mStash.size())
			throw std::runtime_error("");



		for (u64 i = 0; i < mBins.size(); ++i)
		{
			if (mBins[i].mVal != cmp.mBins[i].mVal)
			{
				return false;
			}
		}

		for (u64 i = 0; i < mStash.size(); ++i)
		{
			if (mStash[i].mVal != cmp.mStash[i].mVal)
			{
				return false;
			}
		}

		return true;
	}

	bool PartitionedCuckoo::operator!=(const PartitionedCuckoo& cmp) const
	{
		return !(*this == cmp);
	}

	void PartitionedCuckoo::print() const
	{

		std::cout << "Cuckoo Hasher  " << std::endl;


		for (u64 i = 0; i < mBins.size(); ++i)
		{
			std::cout << "Bin #" << i;

			if (mBins[i].isEmpty())
			{
				std::cout << " - " << std::endl;
			}
			else
			{
				std::cout << "    c_idx=" << mBins[i].idx() << "  hIdx=" << mBins[i].hashIdx() << std::endl;

			}

		}
		for (u64 i = 0; i < mStash.size() && mStash[i].isEmpty() == false; ++i)
		{
			std::cout << "Bin #" << i;

			if (mStash[i].isEmpty())
			{
				std::cout << " - " << std::endl;
			}
			else
			{
				std::cout << "    c_idx=" << mStash[i].idx() << "  hIdx=" << mStash[i].hashIdx() << std::endl;

			}

		}
		std::cout << std::endl;

	}

	void PartitionedCuckoo::init()
	{

		mHashes.resize(mN * mNumHashes, 0);


		mHashesView = MatrixView<u64>(mHashes.begin(), mHashes.end(), mNumHashes);

		u64 binCount = u64(mNumHashes * mPartitionSize);

		mBins.resize(binCount);
		//mStash.resize(mParams.mStashSize);
	}


	void PartitionedCuckoo::insertBatch(
		span<u64> inputIdxs,
		MatrixView<u64> hashs,
		Workspace& w)
	{

		u64 width = mHashesView.bounds()[1];
		u64 remaining = inputIdxs.size();
		u64 tryCount = 0;
		//u64 evists = 0;

#ifndef  NDEBUG
		if (hashs.bounds()[1] != width)
			throw std::runtime_error("" LOCATION);
#endif // ! NDEBUG


		for (u64 i = 0; i < inputIdxs.size(); ++i)
		{
			//std::cout << inputIdxs[i] << " hs ";

			for (u64 j = 0; j < mNumHashes; ++j)
			{
#ifndef  NDEBUG
				mHashesView[inputIdxs[i]][j] = hashs[i][j];
#else
				(mHashesView.data() + inputIdxs[i] * width)[j] = (hashs.data() + i * width)[j];
#endif // ! NDEBUG

				//std::cout << hashs[i][j] << "   ";

			}

			//std::cout << std::endl;

			w.curHashIdxs[i] = 0;
		}


		while (remaining && tryCount++ < 100)
		{

			// this data fetch can be slow (after the first loop).
			// As such, lets do several fetches in parallel.
			for (u64 i = 0; i < remaining; ++i)
			{
#ifndef  NDEBUG
				w.curAddrs[i] = mHashesView[inputIdxs[i]][w.curHashIdxs[i]] % mBins.size();
#else
				w.curAddrs[i] = (mHashesView.data() + inputIdxs[i] * width)[w.curHashIdxs[i]] % mBins.size();
#endif
				//if(inputIdxs[i]  == 8)
				//std::cout <<  i << "   idx " << inputIdxs[i]  <<  "  addr "<< w.curAddrs[i] << std::endl;
			}
			//std::cout << std::endl;

			// same thing here, this fetch is slow. Do them in parallel.
			for (u64 i = 0; i < remaining; ++i)
			{
				u64 newVal = inputIdxs[i] | (w.curHashIdxs[i] << 56);
#ifdef THREAD_SAFE_CUCKOO
				w.oldVals[i] = mBins[w.curAddrs[i]].mVal.exchange(newVal, std::memory_order_relaxed);
#else
				w.oldVals[i] = mBins[w.curAddrs[i]].mVal;
				mBins[w.curAddrs[i]].mVal = newVal;
#endif
				//if (inputIdxs[i] == 8)
				//{

				//	u64 oldIdx = w.oldVals[i] & (u64(-1) >> 8);
				//	u64 oldHash = (w.oldVals[i] >> 56);
				//	std::cout
				//	    << i << "   bin[" << w.curAddrs[i] << "]  "
				//	    << " gets (" << inputIdxs[i] << ", "<< w.curHashIdxs[i]<< "),"
				//	    << " evicts ("<< oldIdx << ", "<< oldHash<< ")" << std::endl;
				//}
			}

			// this loop will update the items that were just evicted. The main
			// idea of that our array looks like
			//     |XW__Y____Z __|
			// For X and W, which failed to be placed, lets write over them
			// with the vaues that they evicted.
			u64 putIdx = 0, getIdx = 0;
			while (putIdx < remaining && w.oldVals[putIdx] != u64(-1))
			{
				inputIdxs[putIdx] = w.oldVals[putIdx] & (u64(-1) >> 8);
				w.curHashIdxs[putIdx] = (1 + (w.oldVals[putIdx] >> 56)) % mNumHashes;
				++putIdx;
			}

			getIdx = putIdx + 1;

			// Now we want an array that looks like
			//  |ABCD___________| but currently have
			//  |AB__Y_____Z____| so lets move them
			// forward and replace Y, Z with the values
			// they evicted.
			while (getIdx < remaining)
			{
				while (getIdx < remaining &&
					w.oldVals[getIdx] == u64(-1))
					++getIdx;

				if (getIdx >= remaining) break;

				inputIdxs[putIdx] = w.oldVals[getIdx] & (u64(-1) >> 8);
				w.curHashIdxs[putIdx] = (1 + (w.oldVals[getIdx] >> 56)) % mNumHashes;

				// not needed. debug only
				//std::swap(w.oldVals[putIdx], w.oldVals[getIdx]);

				++putIdx;
				++getIdx;
			}

			remaining = putIdx;
			//evists += remaining;

			//std::cout << std::endl;
			//for (u64 i = 0; i < remaining; ++i)
			//    std::cout<< "evicted[" << i << "]'  " << inputIdxs[i] << "  " << w.curHashIdxs[i] << std::endl;
			//std::cout << std::endl;

		}

		// put any that remain in the stash.
		for (u64 i = 0; i < remaining; ++i)
		{
			mStash.push_back(Bin(inputIdxs[i], w.curHashIdxs[i]));
			//mStash[j].swap(inputIdxs[i], w.curHashIdxs[i]);

			//if (inputIdxs[i] == u64(-1))
			//    ++i;
		}

		//std::cout << "total evicts "<< evists << std::endl;
	}



	u64 PartitionedCuckoo::findBatch(
		MatrixView<u64> hashes,
		span<u64> idxs,
		Workspace& w)
	{

		if (mNumHashes == 2)
		{
			std::array<u64, 2>  addr;

			for (u64 i = 0; i < hashes.bounds()[0]; ++i)
			{
				idxs[i] = u64(-1);

				addr[0] = (hashes[i][0]) % mBins.size();
				addr[1] = (hashes[i][1]) % mBins.size();

#ifdef THREAD_SAFE_CUCKOO
				w.findVal[i][0] = mBins[addr[0]].mVal.load(std::memory_order::memory_order_relaxed);
				w.findVal[i][1] = mBins[addr[1]].mVal.load(std::memory_order::memory_order_relaxed);
#else
				w.findVal[i][0] = mBins[addr[0]].mVal;
				w.findVal[i][1] = mBins[addr[1]].mVal;
#endif
			}

			for (u64 i = 0; i < hashes.bounds()[0]; ++i)
			{
				if (w.findVal[i][0] != u64(-1))
				{
					u64 itemIdx = w.findVal[i][0] & (u64(-1) >> 8);

					bool match =
						(mHashesView[itemIdx][0] == hashes[i][0]) &&
						(mHashesView[itemIdx][1] == hashes[i][1]);

					if (match) idxs[i] = itemIdx;
				}

				if (w.findVal[i][1] != u64(-1))
				{
					u64 itemIdx = w.findVal[i][1] & (u64(-1) >> 8);

					bool match =
						(mHashesView[itemIdx][0] == hashes[i][0]) &&
						(mHashesView[itemIdx][1] == hashes[i][1]);

					if (match) idxs[i] = itemIdx;
				}

				// stash
				if (idxs[i] == u64(-1))
				{
					u64 j = 0;
					while (j < mStash.size() && mStash[j].isEmpty() == false)
					{
#ifdef THREAD_SAFE_CUCKOO
						u64 val = mStash[j].mVal.load(std::memory_order::memory_order_relaxed);
#else
						u64 val = mStash[j].mVal;
#endif
						if (val != u64(-1))
						{
							u64 itemIdx = val & (u64(-1) >> 8);


							bool match =
								(mHashesView[itemIdx][0] == hashes[i][0]) &&
								(mHashesView[itemIdx][1] == hashes[i][1]);

							if (match)
							{
								idxs[i] = itemIdx;
							}

						}

						++j;
					}
				}

			}


		}
		else
		{
			std::vector<u64> addr(hashes.bounds()[1]);

			for (u64 i = 0; i < hashes.bounds()[0]; ++i)
			{
				idxs[i] = u64(-1);

				for (u64 j = 0; j < hashes.bounds()[1]; ++j)
					addr[j] = hashes[i][j] % mBins.size();

#ifdef THREAD_SAFE_CUCKOO
				for (u64 j = 0; j < hashes.bounds()[1]; ++j)
					w.findVal[i][j] = mBins[addr[j]].mVal.load(std::memory_order::memory_order_relaxed);
#else
				for (u64 j = 0; j < hashes.stride(); ++j)
					w.findVal[i][j] = mBins[addr[j]].mVal;
#endif
			}

			for (u64 i = 0; i < hashes.bounds()[0]; ++i)
			{
				for (u64 j = 0; j < hashes.bounds()[1] && idxs[i] == u64(-1); ++j)
				{

					if (w.findVal[i][j] != u64(-1))
					{
						u64 itemIdx = w.findVal[i][j] & (u64(-1) >> 8);

						bool match = true;

						for (u64 k = 0; k < hashes.bounds()[1]; ++k)
						{
							match &= (mHashesView[itemIdx][k] == hashes[i][k]);
						}

						if (match) idxs[i] = itemIdx;
					}
				}

				// stash
				if (idxs[i] == u64(-1))
				{
					u64 j = 0;
					while (j < mStash.size() && mStash[j].isEmpty() == false)
					{
#ifdef THREAD_SAFE_CUCKOO
						u64 val = mStash[j].mVal.load(std::memory_order::memory_order_relaxed);
#else
						u64 val = mStash[j].mVal;
#endif
						if (val != u64(-1))
						{
							u64 itemIdx = val & (u64(-1) >> 8);
							bool match = true;

							for (u64 k = 0; k < hashes.bounds()[1]; ++k)
							{
								match &= (mHashesView[itemIdx][k] == hashes[i][k]);
							}

							if (match) idxs[i] = itemIdx;

						}

						++j;
					}
				}


			}

		}
		return u64(-1);
	}

	u64 PartitionedCuckoo::stashUtilization()
	{
		u64 i = 0;
		while (i < mStash.size() && mStash[i].isEmpty() == false)
			++i;

		return i;
	}


	bool PartitionedCuckoo::Bin::isEmpty() const
	{
		return mVal == u64(-1);
	}

	u64 PartitionedCuckoo::Bin::idx() const
	{
		return mVal & (u64(-1) >> 8);
	}

	u64 PartitionedCuckoo::Bin::hashIdx() const
	{
		return mVal >> 56;
	}

	void PartitionedCuckoo::Bin::swap(u64& idx, u64& hashIdx)
	{
		u64 newVal = idx | (hashIdx << 56);
		u64 oldVal = mVal;
		mVal = newVal;
		if (oldVal == u64(-1))
		{
			idx = hashIdx = u64(-1);
		}
		else
		{
			idx = oldVal & (u64(-1) >> 8);
			hashIdx = oldVal >> 56;
		}
	}


	void runOne(
		const u64& setSize,
		const u64& h,
		double& e,
		const u64& t,
		const u64& numThrds,
		bool varyCuckooSize,
		const u64& stashSize,
		std::fstream& out,
		bool rand, u64 seed)
	{
		std::vector<std::array<u64, 400>> counts(numThrds);
		memset(counts.data(), 0, sizeof(u64) * 400 * numThrds);
		u64 tries = u64(1) << t;
		auto parSize = 1ull <<log2ceil(divCeil(setSize * e, h));

		auto routine = [
			tries, &counts, setSize, h, e, parSize, 
			numThrds, rand, seed](u64 tIdx)
			{
				PRNG prng(block(seed, tIdx));

				std::vector<block> hashs(setSize);
				std::vector<u64> idxs(setSize);

				u64 startIdx = tIdx * tries / numThrds;
				u64 endIdx = (tIdx + 1) * tries / numThrds;
				u64 count = endIdx - startIdx;

				for (u64 i = 0; i < count; ++i)
				{
					prng.mAes.ecbEncCounterMode(prng.mBlockIdx, setSize, (block*)hashs.data());
					prng.mBlockIdx += setSize;

					for (u64 i = 0; i < setSize; ++i) {
						idxs[i] = i;
					}

					u64 stashSize;

					PartitionedCuckoo cc;
					cc.mN = setSize;
					cc.mNumHashes = h;
					cc.mPartitionSize = parSize;

					cc.init();
					cc.insert(idxs, hashs);
					stashSize = cc.stashUtilization();
					++counts[tIdx][stashSize];

				}

				return 0;
			};

		std::vector<std::thread> thrds(numThrds);

		for (u64 i = 0; i < numThrds; ++i) {
			thrds[i] = std::thread([&, i]() {routine(i); });
		}

		///////////////////////////////////////////////////////////////////
		//               Process printing below here                     //
		///////////////////////////////////////////////////////////////////


		u64 curTotal(0);
		u64 total = (u64(1) << t);
		while ((u64)curTotal != total)
		{
			// the number of times we have seen
			// a stash with a given size.
			std::array<u64, 400> count;
			for (u64 i = 0; i < count.size(); ++i)
				count[i] = 0;

			for (u64 t = 0; t < numThrds; ++t)
				for (u64 i = 0; i < count.size(); ++i)
					count[i] += counts[t][i];

			curTotal = 0;
			for (u64 i = 0; i < count.size(); ++i) {
				curTotal += count[i];
			}

			double percent = curTotal * 10000 / tries / 100.0;

			std::cout << "\r " << std::setw(5) << percent << "%  e=" << 
				e << " |set|=" << setSize << " |par|=" << parSize <<" h="<<h;
			auto p = std::setprecision(3);
			//auto w = std::setw(5);
			u64 good = 0;
			for (u64 i = 0; i < stashSize; ++i)
			{
				// the number of instances with stash size
				// at most i.
				good += count[i];

				// the number of instances with stash size 
				// greater than i.
				u64 bad = curTotal - good;

				// technically this should be log2(curTotal) - log2(bad) but then 
				// the linear growth we see for large secLevel does not continue
				// as it nears 0. Instead we will allow sec level to go negative.
				double secLevel = std::log2(std::max(u64(1), good)) - std::log2(std::max(u64(1), bad));

				if (bad == 0) {
					std::cout << "  >" << std::fixed << p << secLevel;
				}
				else if (good == 0) {
					std::cout
						<< "  <" << std::fixed << p << secLevel;
				}
				else {
					std::cout << "  " << secLevel;
				}
				//std::cout << "  "<< std::fixed <<p << secLevel << "  (" << good << " " << bad<<")";
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}


		std::array<u64, 400> count;
		for (u64 i = 0; i < count.size(); ++i)
			count[i] = 0;

		for (u64 t = 0; t < numThrds; ++t)
			for (u64 i = 0; i < count.size(); ++i)
				count[i] += counts[t][i];

		curTotal = 0;
		for (u64 i = 0; i < count.size(); ++i) {
			curTotal += count[i];
		}

		std::cout << "\re=" << e << "   |set|=" << setSize << " |par|=" << parSize << " h=" << h;
		out << "e " << e << "   |set| " << setSize << " |par|=" << parSize << " h=" << h;
		u64 good = 0;
		for (u64 i = 0; i < stashSize; ++i)
		{
			// the count of all good events;
			good += count[i];

			// the count of all bad events.
			u64 bad = curTotal - good;

			//std::cout << " (" << i<<" "<< good << ", " << bad << ") ";

			double secLevel = std::log2(std::max(u64(1), good)) - std::log2(std::max(u64(1), bad));

			if (bad == 0) {
				//std::cout << "  >" << secLevel;
				out << "  >" << secLevel;
			}
			else if (good == 0) {
				//std::cout << "  <" << secLevel;
				out << "  <" << secLevel;
			}
			else {
				std::cout << "  " << secLevel;
				out << "  " << secLevel << ((secLevel >= t - 5) ? "*" : "");
			}
		}
		std::cout << "                                 " << std::endl;
		out << std::endl;

		//for (u64 i = 0; i < counts.size(); ++i) {
		//    out << i << "  " << count[i] << std::endl;
		//}

		for (u64 i = 0; i < numThrds; ++i) {
			thrds[i].join();
		}

	}

	void simpleTest(CLP cmd)
	{
		//tt();
		//return;

		std::fstream out;
		out.open("./stashSizes.txt", out.out | out.trunc);


		if (cmd.hasValue("nn"))
			cmd.setDefault("n", std::to_string(1ull << cmd.get<u64>("nn")));
		else
			cmd.setDefault("n", "32");

		cmd.setDefault("h", "3");
		cmd.setDefault("e", "1.35");
		cmd.setDefault("t", "12");
		cmd.setDefault("x", "3");
		cmd.setDefault("eStep", "0.05");
		cmd.setDefault("nStep", "2");
		cmd.setDefault("ss", "6");

		// a parameter that shows the security level up to a stash size stashSize. Does not
		// effect performance.
		u64 stashSize = cmd.get<u64>("ss");;
		u64 seed = cmd.getOr("seed", 0);

		// the expension factor. see N.
		const double e = cmd.get<double>("e");

		bool rand = cmd.isSet("rand");

		// N is the size of the hash table. n = N / e items will be inserted...
		// if varyN, we change N and keep the #items fixed at n
		bool varyCuckooSize = !cmd.isSet("veryN");

		// set size = |set| or Cuckoo table size = |cuckoo|
		u64 n, nEnd;
		n = cmd.isSet("nn") ? 1ull << cmd.get<u64>("nn") : cmd.get<u64>("n");
		nEnd = cmd.isSet("nnEnd") ? 1ull << cmd.get<u64>("nnEnd") : n;

		// number of hash functions
		u64 h = cmd.get<u64>("h");

		// log2(...) the number of times we construct the cuckoo table.
		u64 t = cmd.get<u64>("t");

		// the last expansion factor that is considered. If set, all e between e and eEnd in steps of step are tried.
		double eEnd = cmd.isSet("eEnd") ? cmd.get<double>("eEnd") : e;
		// the step size of e that should be tried.
		double eStep = cmd.get<double>("eStep");
		u64 nStep = cmd.get<u64>("nStep");


		// the number of threads
		u64 numThrds = cmd.get<u64>("x");
		std::cout << "#threads=" << numThrds << " h=" << h << "  trials=" << t << " n=" << n << " nEnd=" << nEnd << std::endl;
		//for(u64 n )
		while (n <= nEnd)
		{
			auto curE = e;

			while (eStep > 0 ? curE <= eEnd : curE >= eEnd)
			{
				u64 curSetSize = varyCuckooSize ? n : u64(n / curE);

				runOne(curSetSize, h, curE,
					t, numThrds, varyCuckooSize,
					stashSize, out, rand, seed);
				curE += eStep;
			}

			n *= (1ull << nStep);
		}
		std::cout << std::endl;
	}

	void InvMtxDmpfSimulator(const CLP& cmd)
	{

		simpleTest(cmd);
	}
}
