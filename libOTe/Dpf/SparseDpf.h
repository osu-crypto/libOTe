#pragma once


#include "libOTe/config.h"
#if defined(ENABLE_SPARSE_DPF) 

#include "cryptoTools/Common/Defines.h"
#include "coproto/Socket/Socket.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"
#include "libOTe/Dpf/RegularDpf.h"
#include <limits>

#include <chrono>

namespace osuCrypto
{

	/// Sparse Distributed Point Function (DPF) implementation.
	/// This implements the sparse DPF protocol that evaluates a point function
	/// over a sparse subset S ⊆ [0, 2^D) where |S| << 2^D.
	/// The key optimization is pruning internal nodes with only one child,
	/// achieving O(|S|) work instead of O(2^D) for full domain evaluation.
	struct SparseDpf
	{
		SparseDpf() = default;
		SparseDpf(const SparseDpf&) = delete;
		SparseDpf& operator=(const SparseDpf&) = delete;

		SparseDpf(SparseDpf&& src) noexcept
		{
			*this = std::move(src);
		}

		SparseDpf& operator=(SparseDpf&& src) noexcept
		{
			if (this != &src)
			{
				mPartyIdx = src.mPartyIdx;
				mNumPoints = src.mNumPoints;
				mDomain = src.mDomain;
				mDenseDepth = src.mDenseDepth;
				mLastProfile = src.mLastProfile;
				mProfileEnabled = src.mProfileEnabled;
				mRegDpf = std::move(src.mRegDpf);
				mMultiplier = std::move(src.mMultiplier);
				src.clear();
			}
			return *this;
		}

		struct Profile
		{
			double mAllocateMs = 0;
			double mDenseProtocolMs = 0;
			double mDenseInitializeMs = 0;
			double mCorrectionPrepareMs = 0;
			double mCorrectionProtocolMs = 0;
			double mSparseExpandMs = 0;
			double mLeafMs = 0;
			double mOutputMs = 0;
			u64 mExpandedNodes = 0;
			u64 mBatchedNodes = 0;
			u64 mTailNodes = 0;
		};

		Profile mLastProfile;
		bool mProfileEnabled = false;

		void enableProfile(bool enabled = true)
		{
			mProfileEnabled = enabled;
		}
		u64 mPartyIdx = 0;           // Party index p ∈ {0,1}
		u64 mNumPoints = 0;    // Number of parallel sparse DPF instances
		u64 mDomain = 0;             // Domain size 2^D
		u64 mDenseDepth = 0;         // Optimization: use regular DPF for dense levels


		/// Regular DPF for dense optimization at top levels
		RegularDpf<block> mRegDpf;

		/// Multiplier for computing correction words σ using correctionWord protocol
		DpfMult mMultiplier;

		/// Initialize sparse DPF with domain size and sparse set
		/// @param partyIdx Index of the party (0 or 1)
		/// @param numPoints Number of points in the sparse set S
		/// @param domain Domain size 2^D
		/// @param denseDepth Number of dense levels to optimize with regular DPF
		void init(
			u64 partyIdx,
			u64 numPoints,
			u64 domain,
			u64 denseDepth
		)
		{
			// the implementation assumes the domain is at most 2^32
			// could be generalized.
			if (partyIdx > 1 || numPoints == 0 || domain < 2 ||
				domain > (1ull << 32))
				throw RTE_LOC;

			auto domainDepth = log2ceil(domain);
			auto actualDenseDepth = std::min(denseDepth, domainDepth);
			auto depth = domainDepth - actualDenseDepth;
			if (depth && numPoints > std::numeric_limits<u64>::max() / depth)
				throw RTE_LOC;

			mRegDpf.clear();
			mMultiplier.clear();
			mNumPoints = numPoints;
			mPartyIdx = partyIdx;
			mDomain = domain;
			mDenseDepth = actualDenseDepth;

			// Initialize multiplier for correction word computation at each level
			mMultiplier.init(mPartyIdx, depth * mNumPoints);
			if (mDenseDepth)
				mRegDpf.init(mPartyIdx, 1ull << mDenseDepth, numPoints);
		}

		u8 lsb(const block& b) { return b.get<u8>(0) & 1; }


		bool hasBaseOts() const
		{
			return (!mRegDpf.baseOtCount() || mRegDpf.hasBaseOts()) &&
				(!mMultiplier.baseOtCount() || mMultiplier.hasBaseOts());
		}

		// the number of base OTs required for the protocol. Requires OTs in both directions.
		u64 baseOtCount() const { return log2ceil(mDomain) * mNumPoints; }

		/// Set the base OTs for the sparse DPF protocol.
		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const oc::BitVector& baseChoices)
		{
			auto count = baseOtCount();
			if (baseSendOts.size() != count)
				throw RTE_LOC;
			if (recvBaseOts.size() != count)
				throw RTE_LOC;
			if (baseChoices.size() != count)
				throw RTE_LOC;

			auto denseCount = mRegDpf.baseOtCount();
			auto
				sDense = baseSendOts.subspan(0, denseCount),
				sRest = baseSendOts.subspan(denseCount);

			auto
				rDense = recvBaseOts.subspan(0, denseCount),
				rRest = recvBaseOts.subspan(denseCount);

			BitVector cDense, cRest;
			cDense.append(baseChoices, denseCount);
			cRest.append(baseChoices, count - denseCount, denseCount);

			if (denseCount)
				mRegDpf.setBaseOts(sDense, rDense, cDense);

			mMultiplier.setBaseOts(sRest, rRest, cRest);
		}
		//using Range = std::pair<u32*, u32*>;
		struct Range
		{
			u32* mBegin;
			u32* mEnd;

			Range() = default;
			Range(const Range&) = default;
			Range(u32* b, u32* e) : mBegin(b), mEnd(e) {}

			auto begin() const { return mBegin; }
			auto end() const { return mEnd; }
			auto size() const { return mEnd - mBegin; }
		};

		/// Partition structure representing node state in sparse tree.
		/// The partition contains a range of points that live at this
		/// node, and an iterator to the midpoint that separates the left and right
		/// children.
		struct Partition
		{
			// a span into the sparse set of points that live at this node.
			// an iterator to the midpoint of the range. Left child contains
			// mRange.begin() to mMid, and the right child contains
			// mMid to mRange.end().

			u32* mBegin;
			u32* mMid;
			u32* mEnd;

			//span<u32>::iterator mMid;

			//Partition() = default;
			//Partition(span<u32> range, span<u32>::iterator mid)
			//	: mRange(range), mMid(mid)
			//{ }
			// Returns the left right children ranges of this partition.
			// i.e. in the paper: [l₁,l₂] || [r₁,r₂] = [β₁,β₂]
			std::array<Range, 2> children() const
			{
				return { Range{mBegin, mMid}, Range{mMid, mEnd} };
			}

			std::string print(u64 bitIdx)
			{
				std::stringstream ss;
				ss << "bit " << bitIdx << " val " << (1 << bitIdx) << " {";
				--bitIdx;
				for (auto iter =mBegin; iter != mEnd; ++iter)
				{
					if (iter == mMid)
						ss << ",";

					auto upper = *iter >> bitIdx;
					auto lower = *iter & ((1 << bitIdx) - 1);

					ss << " " << upper << "." << lower;
				}
				ss << "}";
				return ss.str();
			}
		};

		/// Implementation of PARTITION(β ∈ ℕ², S ⊂ ℕ) from Figure 4.
		/// Finds the highest bit δ that splits S_{[β₁,β₂]} into non-empty parts.
		/// Returns (δ, partition) where δ is the split level and partition
		/// describes the left/right index ranges.
		std::pair<u32, Partition> partition(Range points, u32 upperBitsBegin)
		{
			if (points.size() == 0)
				throw RTE_LOC;
			// Step 1: if β₁ = β₂, return (0, (β, ⊥))
			if (points.size() == 1)
				return { 0, Partition{points.begin(), points.end(), points.end()}};

			// The first and last sorted points share exactly the prefix above the
			// highest differing bit. That bit is the unique next trie branch.
			const auto difference = *points.begin() ^ *(points.end() - 1);
			if (difference == 0)
				throw std::invalid_argument("Sparse DPF sets must not contain duplicates. " LOCATION);
			const auto level = static_cast<u32>(std::bit_width(difference));
			if (level > upperBitsBegin)
				throw RTE_LOC;

			const auto highPrefix = (static_cast<u64>(*points.begin()) >> level) << level;
			const auto splitValue = static_cast<u32>(highPrefix | (1ull << (level - 1)));
			const auto mid = std::lower_bound(points.begin(), points.end(), splitValue);
			assert(mid != points.begin() && mid != points.end());
			return { level, Partition{points.mBegin, mid, points.mEnd} };
		}

		/// Tree structure implementing sparse DPF state management.
		/// Maintains state buckets u_d for each level d ∈ [0,D].
		struct Tree
		{
			/// Node corresponding to tuple (j,ρ,b,[s],[t]) in protocol
			struct Node
			{
				block mSeed; // current seed
				u32 mBegin; // offsets into the tree's sorted sparse point set
				u32 mMid;
				u32 mEnd;
				u8 mTag; // current tag, 1 bit;
				u8 mChild; // is this a left 0 or right 1 child?
				u8 mParent; // the depth of the parent. This tells us which sigma to use. in [0,64)

				Partition partition(u32* pointBase) const
				{
					return {
						pointBase + mBegin,
						pointBase + mMid,
						pointBase + mEnd
					};
				}
			};
			static_assert(sizeof(Node) == 32);

			/// Level d state: bucket u_d and running sums z_d
			struct Level
			{
				// Exact-capacity slice of the tree's contiguous node storage.
				span<Node> mNodes_;
				u32* mPointBase = nullptr;
				u64 mNodeSize = 0;

				// the left right sums for each level of the tree.
				std::array<block, 2> mZ;

				// flags to detect if a level of the tree is used.
				u8 mC = 0;

				// the tau correction bits for each level of the tree.
				std::array<u8, 2> mTau;

				// the correction values for each level of the tree
				block mSigma;

				/// Add tuple (j,ρ,b',[s],[t]) to state bucket u_δ
				void push_back(u8 child, u8 parentLevel, Partition& b, block seed, u8 tag) {
					const auto idx = mNodeSize;
					if (idx >= mNodes_.size())
						throw std::runtime_error("Sparse DPF node count mismatch. " LOCATION);
					const auto begin = static_cast<u64>(b.mBegin - mPointBase);
					const auto mid = static_cast<u64>(b.mMid - mPointBase);
					const auto end = static_cast<u64>(b.mEnd - mPointBase);
					if (end > std::numeric_limits<u32>::max())
						throw std::overflow_error("Sparse DPF set exceeds 32-bit node offsets. " LOCATION);
					mNodes_[idx] = Node{
						seed,
						static_cast<u32>(begin),
						static_cast<u32>(mid),
						static_cast<u32>(end),
						tag,
						child,
						parentLevel
					};
					mNodeSize = idx + 1;
				}

				u64 size() const { return mNodeSize; }

				Node& operator[](u64 i)
				{
					assert(i < mNodeSize && "index out of bounds");
					return mNodes_[i];
				}
			};

			// State buckets u_0, u_1, ..., u_D
			std::vector<Level> mLevels;
			AlignedUnVector<Node> mNodeStorage;
			u32* mPointBase = nullptr;

			// Allocate exactly one contiguous slab for all sparse levels.
			void resize(span<const u64> levelSizes, u32* pointBase)
			{
				mLevels.resize(levelSizes.size());
				mPointBase = pointBase;
				u64 totalSize = 0;
				for (auto size : levelSizes)
					totalSize += size;
				mNodeStorage.resize(totalSize);

				u64 offset = 0;
				for (u64 level = 0; level < levelSizes.size(); ++level)
				{
					auto& dst = mLevels[level];
					auto nodeData = totalSize ? mNodeStorage.data() + offset : nullptr;
					dst.mNodes_ = span<Node>(nodeData, levelSizes[level]);
					dst.mPointBase = pointBase;
					dst.mNodeSize = 0;
					offset += levelSizes[level];
				}
			}

			Level& operator[](u64 i) { return mLevels[i]; }
		};

		template<typename SparseSet>
		std::vector<u64> sparseNodeCounts(SparseSet&& sparsePoints, u64 depth)
		{
			std::vector<u64> levelSizes(depth + 1);
			auto begin = sparsePoints.data();
			auto end = begin + sparsePoints.size();
			auto countBin = [&](u32* first, u32* last)
			{
				const auto size = static_cast<u64>(last - first);
				if (size <= 1)
					return;

				// A compressed binary trie with k leaves has k - 1 internal
				// nodes. Each internal node is represented by exactly one boundary
				// between adjacent sorted leaves, at level bit_width(x[i-1]^x[i]).
				// The bin root is not stored, so remove its unique maximum boundary.
				levelSizes[0] += size;
				u32 rootLevel = 0;
				for (auto iter = first + 1; iter != last; ++iter)
				{
					const auto difference = *(iter - 1) ^ *iter;
					if (difference == 0)
						throw std::invalid_argument("Sparse DPF sets must not contain duplicates. " LOCATION);
					const auto level = static_cast<u32>(std::bit_width(difference));
					assert(level <= depth);
					++levelSizes[level];
					rootLevel = std::max(rootLevel, level);
				}
				assert(rootLevel);
				--levelSizes[rootLevel];
			};

			if (mDenseDepth)
			{
				auto iter = begin;
				while (iter != end)
				{
					const auto bin = *iter >> depth;
					auto next = std::find_if(iter, end,
						[bin, depth](auto point) { return (point >> depth) != bin; });
					countBin(iter, next);
					iter = next;
				}
			}
			else
				countBin(begin, end);

			return levelSizes;
		}

		// Keep over-aligned SIMD scratch storage out of the coroutine frame.
		// Some compilers do not over-align coroutine allocations even when a local
		// object requires it. One call handles a complete tree level, so keeping
		// this helper out of line has negligible dispatch cost and preserves the
		// eight-node AES batching in the hot loop.
#if defined(_MSC_VER)
		__declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
		__attribute__((noinline))
#endif
		void expandSparseLevel(Tree& tree, u64 level)
		{
			const auto size = tree[level].size();
			auto z0 = tree[level].mZ[0];
			auto z1 = tree[level].mZ[1];
			u64 i = 0;
			if (mProfileEnabled)
			{
				mLastProfile.mExpandedNodes += size;
				mLastProfile.mBatchedNodes += size / 8 * 8;
				mLastProfile.mTailNodes += size % 8;
			}

			// Expand eight independent active subtrees with one SIMD AES kernel.
			for (; i + 8 <= size; i += 8)
			{
				AlignedArray<block, 8> cSeed0;
				AlignedArray<block, 8> cSeed1;
				std::array<u8, 8> cTag;

				for (u64 lane = 0; lane < 8; ++lane)
				{
					auto& node = tree[level][i + lane];
					const auto tag = node.mTag;
					const auto child = node.mChild;
					const auto parent = node.mParent;
					const auto pTau = tree[parent].mTau[child];
					const auto pSigma = tree[parent].mSigma;
					const auto seed = node.mSeed ^
						(pSigma & block::allSame<u8>(-tag));

					cTag[lane] = lsb(node.mSeed) ^ tag * pTau;
					cSeed0[lane] = seed ^ ZeroBlock;
					cSeed1[lane] = seed ^ OneBlock;
				}

				mAesFixedKey.hashBlocks<8>(cSeed0.data(), cSeed0.data());
				mAesFixedKey.hashBlocks<8>(cSeed1.data(), cSeed1.data());

				for (u64 lane = 0; lane < 8; ++lane)
				{
					z0 ^= cSeed0[lane];
					z1 ^= cSeed1[lane];
					auto par = tree[level][i + lane].partition(tree.mPointBase);
					auto children = par.children();

					auto [leftLevel, leftPartition] = partition(children[0], level);
					tree[leftLevel].push_back(
						0, static_cast<u8>(level), leftPartition, cSeed0[lane], cTag[lane]);

					auto [rightLevel, rightPartition] = partition(children[1], level);
					tree[rightLevel].push_back(
						1, static_cast<u8>(level), rightPartition, cSeed1[lane], cTag[lane]);
				}
			}

			// Scalar tail for levels whose active-node count is not a multiple of eight.
			for (; i < size; ++i)
			{
				auto& node = tree[level][i];
				auto par = node.partition(tree.mPointBase);
				const auto tag = node.mTag;
				const auto child = node.mChild;
				const auto parent = node.mParent;
				const auto pTau = tree[parent].mTau[child];
				const auto pSigma = tree[parent].mSigma;
				const auto cTag = lsb(node.mSeed) ^ tag * pTau;
				const auto seed = node.mSeed ^
					(pSigma & block::allSame<u8>(-tag));

				std::array<block, 2> cSeed;
				cSeed[0] = mAesFixedKey.hashBlock(seed ^ ZeroBlock);
				cSeed[1] = mAesFixedKey.hashBlock(seed ^ OneBlock);
				z0 ^= cSeed[0];
				z1 ^= cSeed[1];

				auto children = par.children();
				for (u64 childIndex = 0; childIndex < 2; ++childIndex)
				{
					auto [childLevel, childPartition] = partition(children[childIndex], level);
					tree[childLevel].push_back(
						static_cast<u8>(childIndex), static_cast<u8>(level),
						childPartition, cSeed[childIndex], cTag);
				}
			}

			if (size)
			{
				tree[level].mZ[0] = z0;
				tree[level].mZ[1] = z1;
				tree[level].mC = 1;
			}
		}

		// Helper template to detect if a type has a `rows()` method
		template <typename T, typename = void>
		struct has_rows : std::false_type {};

		template <typename T>
		struct has_rows<T, std::void_t<decltype(std::declval<T>().rows())>> : std::true_type {};


		/// Main sparse DPF expansion protocol implementing Figure 4.
		/// Evaluates sparse point function over subset S with |S| << 2^D complexity.
		/// 
		/// @tparm Output Callback type that receives expanded values.
		/// @tparam SparsePoints Type representing sparse points S. vector<vectors<u32>> or MatrixView<u32>
		/// 
		/// @param points Sparse points S represented as indices in [0, 2^D)
		/// @param values Optional values for each point in S, can be empty
		/// in which case the active leaf will be random.
		/// @param output Output callback to receive expanded values. Output(treeIdx, leafIdx, value, tag)
		/// should be callable.
		/// @param prng Pseudo-random number generator
		/// @param sparsePoints Sparse points S represented as a vector<vectors<u32>> 
		/// or MatrixView<u32> where each inner vector contains points for a single tree. 
		/// Each can be a different size.
		/// @param sock Communication socket for the protocol
		template<typename Output, typename SparsePoints>
		macoro::task<> expand(
			span<u64> points,
			span<block> values,
			Output&& output,
			PRNG& prng,
			SparsePoints&& sparsePoints,
			coproto::Socket& sock)
		{
			using ProfileClock = std::chrono::steady_clock;
			auto profileNow = [&]()
			{
				return mProfileEnabled ? ProfileClock::now() : ProfileClock::time_point{};
			};
			auto addTime = [&](double& destination, ProfileClock::time_point begin)
			{
				if (mProfileEnabled)
					destination += std::chrono::duration<double, std::milli>(
						ProfileClock::now() - begin).count();
			};
			mLastProfile = {};
			auto profileBegin = profileNow();

			// make sure the output is callable with the expected signature
			static_assert(std::is_invocable_v<Output, u64, u64, block, u8>);

			// make sure the sparsePoints is a vector of vectors or MatrixView<u32>, or similar.
			static_assert(std::is_same_v<std::remove_cvref_t<decltype(sparsePoints[0][0])>, u32>);

			// if we have sparsePoints.rows()  the call that.
			// otherwise sparsePoints.size() is the number of points
			auto rows = [&]() {
				if constexpr (has_rows<SparsePoints>::value)
					return sparsePoints.rows();
				else
					return sparsePoints.size();
				};

			if (rows() != mNumPoints || points.size() != mNumPoints)
				throw RTE_LOC;
			if (values.size() && values.size() != mNumPoints)
				throw RTE_LOC;
			for (u64 i = 0; i < mNumPoints; ++i)
			{
				auto&& set = sparsePoints[i];
				for (u64 j = 0; j < set.size(); ++j)
				{
					if (static_cast<u64>(set[j]) >= mDomain ||
						(j && set[j - 1] >= set[j]))
						throw RTE_LOC;
				}
			}

			// the number of levels in the sparse tree.
			u64 depth = log2ceil(mDomain) - mDenseDepth;
			std::vector<Tree> trees(mNumPoints);

			// STEP 1: Book-keeping initialization
			// Initialize state buckets u_d and running sums z_d for each level
			for (u64 i = 0; i < mNumPoints; ++i)
			{
				auto levelSizes = sparseNodeCounts(sparsePoints[i], depth);
				trees[i].resize(levelSizes, sparsePoints[i].data());
			}

			// Allocate memory for leaf outputs
			struct DirectLeaf
			{
				u64 mTree;
				u64 mIndex;
				block mValue;
				u8 mTag;
			};
			std::unique_ptr<u8[]> mem;
			std::vector<std::span<block>> leafValues(mNumPoints);
			std::vector<std::span<u8>> leafTags(mNumPoints);
			std::vector<DirectLeaf> directLeaves;
			u64 totalSize = 0;
			for (u64 i = 0; i < mNumPoints; ++i)
				totalSize += sparsePoints[i].size();

			if (values.size())
			{
				mem.reset(new u8[totalSize * (sizeof(block) + 1)]);
				auto iter = mem.get();
				for (u64 i = 0; i < mNumPoints; ++i)
				{
					leafValues[i] = span<block>((block*)iter, sparsePoints[i].size());
					iter += leafValues[i].size_bytes();
				}
				for (u64 i = 0; i < mNumPoints; ++i)
				{
					leafTags[i] = span<u8>(iter, sparsePoints[i].size());
					iter += leafTags[i].size_bytes();
				}
			}

			// Initialize γ for updateLeaves protocol (step 8)
			std::vector<block> gamma(values.begin(), values.end());
			addTime(mLastProfile.mAllocateMs, profileBegin);


			// DENSE OPTIMIZATION: Use regular DPF for top mDenseDepth levels
			if (mDenseDepth)
			{
				// optimization, for the first mDenseDepth levels, use a regular DPF.
				// since its safe to assume these levels will be dense its more efficient
				// to use a regular DPF to expand the points and then use the seeds

				if (mDenseDepth > log2ceil(mDomain))
					throw RTE_LOC;

				// Extract upper bits for dense evaluation
				std::vector<u64> densePoints(points.size());
				for (u64 i = 0; i < points.size(); ++i)
				{
					// Figure 7 permits an empty public sparse set. Such an instance has
					// no output leaves, so use a public in-domain point for the batched
					// dense expansion and discard its tree below.
					densePoints[i] = sparsePoints[i].size() ? points[i] >> depth : 0;
				}
				Matrix<block> seeds(points.size(), 1ull << mDenseDepth);
				Matrix<u8> tags(points.size(), 1ull << mDenseDepth);

				// Expand regular DPF to get seeds for sparse layers
				profileBegin = profileNow();
				co_await mRegDpf.expand(densePoints, std::vector<block>{}, prng, sock, [&](auto treeIdx, auto leafIdx, auto seed, block tag) {
					seeds(treeIdx, leafIdx) = seed;
					tags(treeIdx, leafIdx) = tag.get<u8>(0) & 1;
					});
				addTime(mLastProfile.mDenseProtocolMs, profileBegin);

				// STEP 3,4: Partitioning the root (adapted for dense optimization)
				profileBegin = profileNow();
				for (u64 r = 0; r < points.size(); ++r)
				{
					auto& tree = trees[r];
					auto iter = sparsePoints[r].data();
					auto end = iter + sparsePoints[r].size();
					while (iter != end)
					{
						auto p = *iter;
						auto bin = p >> depth;
						auto seed = seeds(r, bin);
						auto tag = tags(r, bin);

						// Group sparse points by dense bin
						auto e = std::find_if(iter, end, [bin, depth](auto v) {return (v >> depth) != bin; });
						auto points = Range(iter, e);
						if (points.size() == 1)
						{
							// Single point: direct leaf assignment
							auto idx = std::distance(sparsePoints[r].data(), points.begin());
							if (gamma.size())
							{
								leafValues[r][idx] = seed;
								leafTags[r][idx] = tag;
								gamma[r] ^= seed;
							}
							else
								directLeaves.push_back({ r, static_cast<u64>(idx), seed, tag });
						}
						else if (points.size())
						{
							// Multiple points: partition and create children
							// (δ,b) := PARTITION((1,|points|), points)
							auto [delta, root] = partition(points, depth);

							// Generate children seeds: s'_p := G(s_p)
							block cSeeds[2];
							cSeeds[0] = mAesFixedKey.hashBlock(seed ^ ZeroBlock);
							cSeeds[1] = mAesFixedKey.hashBlock(seed ^ OneBlock);
							auto children = root.children();
							for (u64 j = 0; j < 2; ++j)
							{
								auto [delta2, b2] = partition(children[j], delta);
								tree[delta2].push_back(j, delta, b2, cSeeds[j], tag);
								tree[delta].mZ[j] ^= cSeeds[j];
								tree[delta].mC = 1;
							}
						}
						iter = e;
					}
				}
				addTime(mLastProfile.mDenseInitializeMs, profileBegin);
			}
			else
			{
				profileBegin = profileNow();
				// STEP 3,4: Partitioning the root (no dense optimization)
				for (u64 r = 0; r < mNumPoints; ++r)
				{
					Range points{ sparsePoints[r].data(), sparsePoints[r].data() + sparsePoints[r].size() };
					auto& tree = trees[r];
					if (points.size() == 0)
						continue;
					if (points.size() == 1)
					{
						leafValues[r][0] = prng.get();
						leafTags[r][0] = mPartyIdx;
						if (gamma.size())
							gamma[r] = gamma[r] ^ leafValues[r][0];
						continue;
					}
					// (δ,b) := PARTITION((1,|S|), S)
					auto [delta, b] = partition(points, depth);
					auto children = b.children();
					for (u64 j = 0; j < 2; ++j)
					{
						// (δ',b') := PARTITION(b_j, S)
						auto [delta2, b2] = partition(children[j], delta);
						block seed = prng.get(); // [s] ← {0,1}^κ
						// state_δ' := append(state_δ', (j,δ,b',[s],[1]))
						tree[delta2].push_back(j, delta, b2, seed, mPartyIdx);
						tree[delta].mZ[j] = seed; // z_{δ,j} := [s]
						tree[delta].mC = 1; // v_δ = 1
					}
				}
				addTime(mLastProfile.mDenseInitializeMs, profileBegin);
			}


			// STEP 5,6: Top-down expansion (d ∈ {D, D-1, ..., 1})
			for (u64 d = depth; d; --d)
			{
				profileBegin = profileNow();
				// Collect correction data for all trees at level d
				BitVector negAlpha(mNumPoints);
				std::vector<std::array<u8, 2>> taus(mNumPoints);
				std::vector<block>  sigmas(mNumPoints);
				bool used = false;

				for (u64 r = 0; r < mNumPoints; ++r)
				{
					auto& tree = trees[r];

					// 6a: Randomizing the sums if level unused
					// z_d := z_d ⊕ (¬v_d) · r where r ← {0,1}^{2×κ}
					if (tree[d].mC == 0)
						tree[d].mZ = prng.get();
					else
						used = true;

					// Extract bit α_d from secret point α
					auto alphaD = sparsePoints[r].size() ?
						(points[r] >> (d - 1)) & 1 : 0;

					// Prepare for correctionWord protocol
					taus[r][0] = lsb(tree[d].mZ[0]) ^ alphaD ^ mPartyIdx;
					taus[r][1] = lsb(tree[d].mZ[1]) ^ alphaD;
					negAlpha[r] = alphaD ^ mPartyIdx;
					sigmas[r] = tree[d].mZ[0] ^ tree[d].mZ[1];
				}
				addTime(mLastProfile.mCorrectionPrepareMs, profileBegin);

				if (used)
				{
					profileBegin = profileNow();
					// 6b: Compute and reveal correction words
					// σ := correctionWord(z_d, α_d)
					co_await mMultiplier.multiply(negAlpha, sigmas, sigmas, sock);
					for (u64 r = 0; r < mNumPoints; ++r)
						sigmas[r] = sigmas[r] ^ trees[r][d].mZ[0];
					co_await reveal(sigmas, taus, sock);

					// Store correction words
					for (u64 r = 0; r < mNumPoints; ++r)
					{
						trees[r][d].mSigma = sigmas[r];
						trees[r][d].mTau = taus[r];
					}
					addTime(mLastProfile.mCorrectionProtocolMs, profileBegin);
				}

				auto dNext = d - 1;
				if (dNext == 0) break;// Stop before leaf processing

				// 6c: Updating the shares and computing children
				profileBegin = profileNow();
				for (u64 r = 0; r < mNumPoints; ++r)
				{
					auto& tree = trees[r];
					expandSparseLevel(tree, dNext);
				}
				addTime(mLastProfile.mSparseExpandMs, profileBegin);
			}

			// STEP 7: Leaf processing
			// Process tuples in u_0 (leaf level)
			profileBegin = profileNow();
			if (gamma.empty())
				for (const auto& leaf : directLeaves)
					output(leaf.mTree, leaf.mIndex, leaf.mValue, leaf.mTag);

			for (u64 r = 0; r < mNumPoints; ++r)
			{
				auto& tree = trees[r];
				auto size = tree[0].size();

				for (u64 i = 0; i < size; ++i)
				{
					auto& seed = tree[0][i].mSeed;
					auto tag = tree[0][i].mTag;
					auto j = tree[0][i].mChild;
					auto parent = tree[0][i].mParent;

					// Apply final correction: [s] := [s] ⊕ [t] · σ_{ρ,j}
					auto pTau = tree[parent].mTau[j];
					auto pSigma = tree[parent].mSigma;
					
					// Convert to leaf values:
					// [t_{b₁}] := lsb([s])
					// [y_{b₁}] := (1-2p) · convert_G(msbs([s]))
					auto b = tree[0][i].mBegin;
					const auto leafTag = lsb(seed) ^ tag * pTau;
					const auto leafValue = seed ^ (pSigma & block::allSame<u8>(-tag));
					if (gamma.size())
					{
						leafTags[r][b] = leafTag;
						leafValues[r][b] = leafValue;
						gamma[r] ^= leafValue;
					}
					else
						output(r, b, leafValue, leafTag);
				}
			}
			addTime(mLastProfile.mLeafMs, profileBegin);

			// STEP 8: Derandomizing the leaves
			// return updateLeaves_S([y], [t], [β])
			profileBegin = profileNow();
			if (gamma.size())
			{
				// Reveal γ and apply to convert random unit vector to desired values
				co_await reveal(gamma, sock);
				for (u64 r = 0; r < mNumPoints; ++r)
				{
					auto size = sparsePoints[r].size();
					for (u64 i = 0; i < size; ++i)
					{
						assert(leafValues[r][i] != oc::ZeroBlock);
						// Apply γ correction: γ & allSame(-tag) selects active leaf
						auto val = leafValues[r][i] ^ (gamma[r] & block::allSame<u8>(-leafTags[r][i]));
						output(r, i, val, leafTags[r][i]);
					}
				}
			}
			else
			{
				// Punctured mode emits finalized leaves directly in step 7.
			}
			addTime(mLastProfile.mOutputMs, profileBegin);


			//u64 total = 0;
			//u64 used = 0;
			//for (u64 r = 0; r < mNumPoints; ++r)
			//{
			//	for(u64 j = 0; j < trees[r].mLevels.size(); ++j)
			//	{
			//		total += trees[r][j].mNodes_.size();
			//		used += trees[r][j].mNodeSize;
			//		std::cout << double(trees[r][j].mNodeSize) / double(trees[r][j].mNodes_.size()) << " ";
			//	}
			//	std::cout << std::endl;
			//}
			//std::cout << "SparseDpf: total nodes " << total << ", used nodes " << used << " ~ " << double(used) / total << std::endl;

			co_return;
		}


		macoro::task<> reveal(span<block> sigma, span<std::array<u8, 2>> tau, coproto::Socket& sock)
		{
			if (sigma.size() != tau.size())
				throw RTE_LOC;
			std::vector<block> sBuff(sigma.begin(), sigma.end());
			std::vector<std::array<u8, 2>> tBuff(tau.begin(), tau.end());
			auto sendResults = co_await macoro::when_all_ready(
				sock.send(std::move(sBuff)),
				sock.send(std::move(tBuff))
			);
			std::get<0>(sendResults).result();
			std::get<1>(sendResults).result();
			sBuff.resize(sigma.size());
			tBuff.resize(tau.size());
			auto recvResults = co_await macoro::when_all_ready(
				sock.recv(sBuff),
				sock.recv(tBuff)
			);
			std::get<0>(recvResults).result();
			std::get<1>(recvResults).result();
			for (u64 i = 0; i < sigma.size(); ++i)
				if (tBuff[i][0] > 1 || tBuff[i][1] > 1)
					throw std::runtime_error("SparseDpf received a non-bit tau value. " LOCATION);
			for (u64 i = 0; i < sigma.size(); ++i)
			{
				sigma[i] = sigma[i] ^ sBuff[i];
				tau[i][0] = tau[i][0] ^ tBuff[i][0];
				tau[i][1] = tau[i][1] ^ tBuff[i][1];
			}
		}


		macoro::task<> reveal(span<block> sigma, coproto::Socket& sock)
		{
			std::vector<block> sBuff(sigma.begin(), sigma.end());
			co_await sock.send(std::move(sBuff));
			sBuff.resize(sigma.size());
			co_await  sock.recv(sBuff);
			for (u64 i = 0; i < sigma.size(); ++i)
			{
				sigma[i] = sigma[i] ^ sBuff[i];
			}
		}
		

		void clear()
		{
			mPartyIdx = 0;           // Party index p ∈ {0,1}
			mNumPoints = 0;    // Number of parallel sparse DPF instances
			mDomain = 0;             // Domain size 2^D
			mDenseDepth = 0;         // Optimization: use regular DPF for dense levels
			mLastProfile = {};
			mProfileEnabled = false;
			mRegDpf.clear();
			mMultiplier.clear();

		}
	};

}

#undef SIMD8

#endif
