#pragma once


#include "libOTe/config.h"
#if defined(ENABLE_SPARSE_DPF) 

#include "cryptoTools/Common/Defines.h"
#include "coproto/Socket/Socket.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"
#include "libOTe/Dpf/RegularDpf.h"

namespace osuCrypto
{

	/// Sparse Distributed Point Function (DPF) implementation.
	/// This implements the sparse DPF protocol that evaluates a point function
	/// over a sparse subset S ⊆ [0, 2^D) where |S| << 2^D.
	/// The key optimization is pruning internal nodes with only one child,
	/// achieving O(|S|) work instead of O(2^D) for full domain evaluation.
	struct SparseDpf
	{
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
			mNumPoints = numPoints;
			mPartyIdx = partyIdx;
			mDomain = domain;
			mDenseDepth = std::min(denseDepth, log2ceil(mDomain));
			auto depth = log2ceil(mDomain) - mDenseDepth;

			// the implementation assumes the domain is at most 2^32
			// could be generalized.
			if(domain > 1ull<< 32)
				throw RTE_LOC;

			// Initialize multiplier for correction word computation at each level
			mMultiplier.init(mPartyIdx, depth * mNumPoints);
			if (mDenseDepth)
				mRegDpf.init(mPartyIdx, 1ull << mDenseDepth, numPoints);
		}

		u8 lsb(const block& b) { return b.get<u8>(0) & 1; }


		bool hasBaseOts() const
		{
			return mRegDpf.hasBaseOts();
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
			std::array<Range, 2>  children()
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
			// Step 1: if β₁ = β₂, return (0, (β, ⊥))
			if (points.size() == 1)
				return { 0, Partition{points.begin(), points.end(), points.end()}};
#ifndef NDEBUG
			if (std::adjacent_find(points.begin(), points.end(), std::greater<u32>{}) != points.end())
				throw RTE_LOC;
			if (std::any_of(points.begin(), points.end(),
				[upperBitsBegin, prefix = *points.begin() >> (upperBitsBegin)](auto v) {return v >> (upperBitsBegin) != prefix; }))
				throw RTE_LOC;
			if (points.size() <= 1)
				throw RTE_LOC;
#endif

			// Step 2: Find max δ where bit δ splits the range into {0,1}
			Partition par;
			do {
				assert(upperBitsBegin != 0);
				--upperBitsBegin;
				// Step 3: Split based on bit sδ values
				par.mMid = std::upper_bound(
					points.begin(), points.end(), 0,
					[upperBitsBegin](auto, auto b) {return (b >> upperBitsBegin) & 1; });
			} while (par.mMid == points.begin() || par.mMid == points.end());

			par.mBegin = points.mBegin;
			par.mEnd = points.mEnd;
			return { upperBitsBegin + 1, par };
		}

		/// Tree structure implementing sparse DPF state management.
		/// Maintains state buckets u_d for each level d ∈ [0,D].
		struct Tree
		{
			/// Node corresponding to tuple (j,ρ,b,[s],[t]) in protocol
			struct Node
			{
				Partition mPartition; // the child partitions
				block mSeed; // current seed
				u8 mTag; // current tag, 1 bit;
				u8 mChild; // is this a left 0 or right 1 child?
				u8 mParent; // the depth of the parent. This tells us which sigma to use. in [0,64)
			};

			/// Level d state: bucket u_d and running sums z_d
			struct Level
			{
				// the nodes for each level of the tree.
				AlignedUnVector<Node> mNodes_;

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
					auto idx = mNodeSize++;
					assert(mNodeSize <= mNodes_.size() && "in resize(...) we reserved space so we shouldnt need to reallocate");
					//if (mNodeSize > mNodes_.size())
					//	throw RTE_LOC;
					mNodes_[idx] = Node{ b, seed, tag, child, parentLevel };
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

			// the number of sparse levels and the dense depth.
			void resize(u64 depth, u64 startingDepth, u64 setSize)
			{
				mLevels.resize(depth);
				mLevels[0].mNodes_.resize(setSize);

				// we reserve space for the nodes in each level.
				// we reserve the worse case of 2^depth nodes.
				for (u64 j = 0; j < depth; ++j)
				{
					auto size = std::min<u64>(setSize, 1ull << (startingDepth + j));
					auto half = depth / 2;

					// Linear scale from 1 to 2 once j >= half
					//double scale = (j >= half) ? 1.0 + double(j - half) / double(depth - 1 - half) : 1.0;
					mLevels[mLevels.size() - j - 1].mNodes_.resize(size);
				}
			}

			Level& operator[](u64 i) { return mLevels[i]; }
		};

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

			if (points.size() != rows())
				throw RTE_LOC;
			if (values.size() && values.size() != rows())
				throw RTE_LOC;

			// the number of levels in the sparse tree.
			u64 depth = log2ceil(mDomain) - mDenseDepth;
			std::vector<Tree> trees(mNumPoints);

			// STEP 1: Book-keeping initialization
			// Initialize state buckets u_d and running sums z_d for each level
			for (u64 i = 0; i < mNumPoints; ++i)
				trees[i].resize(depth + 1, mDenseDepth, sparsePoints[i].size());

			// Allocate memory for leaf outputs
			std::unique_ptr<u8[]> mem;
			std::vector<std::span<block>> leafValues(mNumPoints);
			std::vector<std::span<u8>> leafTags(mNumPoints);
			u64 totalSize = 0;
			for (u64 i = 0; i < mNumPoints; ++i)
				totalSize += sparsePoints[i].size();

			mem.reset(new u8[totalSize * (sizeof(block) + 1)]());
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

			// Initialize γ for updateLeaves protocol (step 8)
			std::vector<block> gamma(values.begin(), values.end());


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
					densePoints[i] = points[i] >> depth;
				Matrix<block> seeds(points.size(), 1ull << mDenseDepth);
				Matrix<u8> tags(points.size(), 1ull << mDenseDepth);

				// Expand regular DPF to get seeds for sparse layers
				co_await mRegDpf.expand(densePoints, std::vector<block>{}, prng, sock, [&](auto treeIdx, auto leafIdx, auto seed, block tag) {
					seeds(treeIdx, leafIdx) = seed;
					tags(treeIdx, leafIdx) = tag.get<u8>(0) & 1;
					});

				// STEP 3,4: Partitioning the root (adapted for dense optimization)
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
							leafValues[r][idx] = seed;
							leafTags[r][idx] = tag;

							if (gamma.size())
								gamma[r] = gamma[r] ^ leafValues[r][idx];
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
			}
			else
			{
				// STEP 3,4: Partitioning the root (no dense optimization)
				for (u64 r = 0; r < mNumPoints; ++r)
				{
					Range points{ sparsePoints[r].data(), sparsePoints[r].data() + sparsePoints[r].size() };
					auto& tree = trees[r];
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
			}


			// STEP 5,6: Top-down expansion (d ∈ {D, D-1, ..., 1})
			for (u64 d = depth; d; --d)
			{
				// Collect correction data for all trees at level d
				std::vector<block> z0(mNumPoints);
				std::vector<block> z1(mNumPoints);
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
					auto alphaD = (points[r] >> (d - 1)) & 1;

					// Prepare for correctionWord protocol
					taus[r][0] = lsb(tree[d].mZ[0]) ^ alphaD ^ mPartyIdx;
					taus[r][1] = lsb(tree[d].mZ[1]) ^ alphaD;
					negAlpha[r] = alphaD ^ mPartyIdx;
					sigmas[r] = tree[d].mZ[0] ^ tree[d].mZ[1];

					z0[r] = tree[d].mZ[0];
					z1[r] = tree[d].mZ[1];
				}

				if (used)
				{
					// 6b: Compute and reveal correction words
					// σ := correctionWord(z_d, α_d)
					co_await reveal(z0, sock);
					co_await reveal(z1, sock);
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
				}

				auto dNext = d - 1;
				if (dNext == 0) break;// Stop before leaf processing

				// 6c: Updating the shares and computing children
				for (u64 r = 0; r < mNumPoints; ++r)
				{
					auto& tree = trees[r];
					auto size = tree[dNext].size();

					// Process each tuple (j,ρ,b,[s],[t]) ∈ u_d
					for (u64 i = 0; i < size; ++i)
					{
						auto& node = tree[dNext][i];
						auto& seed = node.mSeed;
						auto par = node.mPartition;
						auto tag = node.mTag;
						auto child = node.mChild;
						auto parent = node.mParent;

						// Get correction from parent level
						auto pTau = tree[parent].mTau[child];
						auto pSigma = tree[parent].mSigma;

						// 6c: [s] := [s] ⊕ [t] · σ_{ρ,j}
						auto cTag = lsb(seed) ^ tag * pTau;
						seed = seed ^ (pSigma & block::allSame<u8>(-tag));

						// 6d: Computing child values: s'_p := G(s_p)
						std::array<block, 2> cSeed;
						cSeed[0] = mAesFixedKey.hashBlock(seed ^ ZeroBlock);
						cSeed[1] = mAesFixedKey.hashBlock(seed ^ OneBlock);

						// Update running sums: z_{d-1} := z_{d-1} ⊕ s'
						tree[dNext].mZ[0] = tree[dNext].mZ[0] ^ cSeed[0];
						tree[dNext].mZ[1] = tree[dNext].mZ[1] ^ cSeed[1];
						tree[dNext].mC = 1;

						// 6e: Partitioning the children
						auto children = par.children();
						for (u64 j = 0; j < 2; ++j)
						{
							// (δ,b') := PARTITION(b_k, S)
							auto [cd, cPar] = partition(children[j], dNext);
							// state_δ := append(state_δ, (k,d-1,b',[s'_k],lsb([s])))
							tree[cd].push_back(j, dNext, cPar, cSeed[j], cTag);
						}
					}
				}
			}

			// STEP 7: Leaf processing
			// Process tuples in u_0 (leaf level)
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
					auto par = tree[0][i].mPartition;

					// Apply final correction: [s] := [s] ⊕ [t] · σ_{ρ,j}
					auto pTau = tree[parent].mTau[j];
					auto pSigma = tree[parent].mSigma;
					
					// Convert to leaf values:
					// [t_{b₁}] := lsb([s])
					// [y_{b₁}] := (1-2p) · convert_G(msbs([s]))
					auto b = std::distance(sparsePoints[r].data(), par.mBegin);
					leafTags[r][b] = lsb(seed) ^ tag * pTau;
					leafValues[r][b] = seed ^ (pSigma & block::allSame<u8>(-tag));

					// Accumulate for updateLeaves protocol
					if (gamma.size())
						gamma[r] = gamma[r] ^ leafValues[r][b];
				}
			}

			// STEP 8: Derandomizing the leaves
			// return updateLeaves_S([y], [t], [β])
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
				// Punctured mode: output raw leaf values
				for (u64 r = 0; r < mNumPoints; ++r)
				{
					auto size = sparsePoints[r].size();
					for (u64 i = 0; i < size; ++i)
					{
						output(r, i, leafValues[r][i], leafTags[r][i]);
					}
				}
			}


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
			co_await macoro::when_all_ready(
				sock.send(std::move(sBuff)),
				sock.send(std::move(tBuff))
			);
			sBuff.resize(sigma.size());
			tBuff.resize(tau.size());
			co_await macoro::when_all_ready(
				sock.recv(sBuff),
				sock.recv(tBuff)
			);
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

	};

}

#undef SIMD8

#endif