#pragma once
#include <libOTe/config.h>

#include <algorithm>
#include <memory>
#include <tuple>
#include <type_traits>
#include <utility>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Aligned.h>
#include <cryptoTools/Network/Channel.h>
#include <boost/mp11/tuple.hpp>

namespace osuCrypto
{

	// TODO: Parallelization should probably be implemented here somewhere.

	// Helper for some template meta-programming.
	template<typename T>
	struct TupleOfUniquePtrs {};

	template<typename... InstParams>
	struct TupleOfUniquePtrs<std::tuple<InstParams...>>
	{
		typedef std::tuple<AlignedUnVector<typename std::remove_const<InstParams>::type...>> type;
	};

	template<typename Ptr>
	struct ChunkerAlloc;

	// Required definitions inside any class inheriting from Chunker:
	/*
	// Number of instances that are done at once.
	size_t chunkSize() const;

	// Number of instances worth of extra data that it should be allowed to read/write, above the
	// chunkSize instances that are actually used.
	size_t paddingSize() const;

	// All spans will have the same size: chunkSize + paddingSize. numUsed is the number (<=
	// chunkSize) of instances that will actually be used, out of the chunkSize instances.
	// chunkParams are parameters that are given once per chunk, and globalParams are given once for
	// the whole batch. This doesn't have to be defined for all template parameter. The template
	// parameters just illustrate the class of functions that are allowed.
	template<typename... ChunkParams, typename... GlobalParams>
	void processChunk(size_t chunkIdx, size_t numUsed, span<InstParams>... instParams,
					  ChunkParams... chunkParams, GlobalParams... globalParams);
	*/

	// For ChunkedSender
	/*
	// Maximum number of chunks to build up before calling sendBuffer
	static const size_t commSize = Derived::commSize;

	// Reserve the memory for a batch of batchSize chunks.
	void reserveSendBuffer(size_t batchSize);

	// Send the data built up in the buffer.
	void sendBuffer(Channel& chl);
	*/

	// For ChunkedReceiver
	/*
	// Maximum number of chunks to get from recvBuffer at a time.
	static const size_t commSize = Derived::commSize;

	// Receive enough data into the internal buffer to perform exactly batchSize chunks.
	void recvBuffer(Channel& chl, size_t batchSize);
	*/

	// The InstParams lists the parameter types of each instance. Once wrapped in span<>, these become
	// parameters of runBatch. InstParams is wrapped in a tuple<> to get T, to encode a variadic in a
	// type. InstParamPtrs (encoded into a tuple as C) is a list of smart pointers that will be used to
	// store temporaries of type InstParams[]... (with any const removed), and each such smart pointer
	// must specialize ChunkerAlloc.

	template<
		typename Derived,
		typename T,
		typename C = typename TupleOfUniquePtrs<T>::type,
		typename I = std::make_index_sequence<std::tuple_size<T>::value>
	>
		class Chunker {};

	// Partial specialization to get access to the parameter packs.
	template<
		typename Derived,
		typename... InstParams,
		typename... InstParamPtrs,
		size_t... InstIndices
	>
		class Chunker<
		Derived,
		std::tuple<InstParams...>,
		std::tuple<InstParamPtrs...>,
		std::integer_sequence<size_t, InstIndices...>>
	{
	protected:
		// Derved* forces correct inheritance (https://stackoverflow.com/a/4418038/4071916)
		Chunker(Derived* this_) {}

	public:
		using InstanceParams = std::tuple<InstParams...>;

		// Use temporaries to make processChunk work on a partial chunk.
		template<typename... ChunkParams, typename... GlobalParams>
		OC_FORCEINLINE void processPartialChunk_(
			size_t chunkIdx, size_t numUsed, size_t minInstances, span<InstParams>... instParams,
			ChunkParams... chunkParams, GlobalParams&&... globalParams)
		{
			// Copy the data into the temporaries. tuple_transform requires a non-void return type.
			using boost::mp11::tuple_transform;
			tuple_transform(
				[=](auto in, const auto& out) { std::copy_n(in, numUsed, out.data()); return 0; },
				std::make_tuple(instParams.data()...), tempStorage);

			static_cast<Derived*>(this)->processChunk(
				chunkIdx, numUsed,
				span<InstParams>(std::get<InstIndices>(tempStorage).data(), minInstances)...,
				std::forward<ChunkParams>(chunkParams)...,
				std::forward<GlobalParams>(globalParams)...);

			// And copy it back out again. The compiler should hopefully be smart enough to remove
			// the first copy if processChunk is write only. (TODO: check).
			tuple_transform(CopyOutFunc{ numUsed }, tempStorage,
				std::make_tuple(instParams.data()...));
		}


		// Use temporaries to make processChunk work on a partial chunk.
		template<typename... GlobalParams>
		OC_FORCEINLINE void processPartialChunk(
			size_t chunkIdx, size_t numUsed, size_t minInstances, span<InstParams>... instParams,
			GlobalParams&&... globalParams)
		{
			// Copy the data into the temporaries. tuple_transform requires a non-void return type.
			using boost::mp11::tuple_transform;
			tuple_transform(
				[=](auto in, const auto& out) { std::copy_n(in, numUsed, out.data()); return 0; },
				std::make_tuple(instParams.data()...), tempStorage);

			static_cast<Derived*>(this)->processChunk(
				chunkIdx, numUsed,
				span<InstParams>(std::get<InstIndices>(tempStorage).data(), minInstances)...,
				std::forward<GlobalParams>(globalParams)...);

			// And copy it back out again. The compiler should hopefully be smart enough to remove
			// the first copy if processChunk is write only. (TODO: check).
			tuple_transform(CopyOutFunc{ numUsed }, tempStorage,
				std::make_tuple(instParams.data()...));
		}


		// Helper to copy to a pointer unless it points to const.
		struct CopyOutFunc
		{
			size_t n;

			template<typename T, typename U>
			int operator()(const T& in, const U* out) const { return 0; }
			template<typename T, typename U>
			int operator()(const T& in, U* out) const { std::copy_n(in.data(), n, out); return 0; }
		};

		std::pair<size_t, size_t>
			checkSpanLengths(span<InstParams>... instParams) const
		{
			size_t numInstancesArray[] = { (size_t)instParams.size()... };
			size_t numInstances = numInstancesArray[0];
#ifndef NDEBUG
			for (size_t n : numInstancesArray)
				if (n != numInstances)
					throw RTE_LOC;
#endif

			const size_t chunkSize = static_cast<const Derived*>(this)->chunkSize();
			size_t numChunks = divCeil(numInstances, chunkSize);
			return std::pair<size_t, size_t>(numInstances, numChunks);
		}


		template<typename... ChunkParams>
		std::pair<size_t, size_t>
			checkSpanLengths(span<InstParams>... instParams, span<ChunkParams>... chunkParams) const
		{
			size_t numInstancesArray[] = { (size_t)instParams.size()... };
			size_t numInstances = numInstancesArray[0];
#ifndef NDEBUG
			for (size_t n : numInstancesArray)
				if (n != numInstances)
					throw RTE_LOC;
#endif

			const size_t chunkSize = static_cast<const Derived*>(this)->chunkSize();
			size_t numChunks = divCeil(numInstances, chunkSize);
#ifndef NDEBUG
			size_t numChunksArray[] = { (size_t)chunkParams.size()... };
			for (size_t n : numChunksArray)
				if (n != numChunks)
					throw RTE_LOC;
#endif

			return std::pair<size_t, size_t>(numInstances, numChunks);
		}

		template<typename... ChunkParams, typename... GlobalParams>
		OC_FORCEINLINE void runBatch(
			Channel& chl, span<InstParams>... instParams,
			span<ChunkParams>... chunkParams, GlobalParams&&... globalParams)
		{
			size_t numInstances = checkSpanLengths(instParams..., chunkParams...).first;

			const size_t chunkSize = static_cast<const Derived*>(this)->chunkSize();
			const size_t minInstances = chunkSize + static_cast<Derived*>(this)->paddingSize();

			// The bulk of the instances can work directly on the input / output data.
			size_t nChunk = 0;
			size_t nInstance = 0;
			for (; nInstance + minInstances <= numInstances; ++nChunk, nInstance += chunkSize)
				static_cast<Derived*>(this)->processChunk(
					nChunk, chunkSize,
					span<InstParams>(instParams.data() + nInstance, minInstances)...,
					std::forward<ChunkParams>(chunkParams[nChunk])...,
					std::forward<GlobalParams>(globalParams)...);

			// The last few (probably only 1) need an intermediate buffer.
			for (; nInstance < numInstances; ++nChunk, nInstance += chunkSize)
			{
				size_t numUsed = std::min(numInstances - nInstance, chunkSize);
				processPartialChunk<ChunkParams...>(
					nChunk, numUsed, minInstances,
					span<InstParams>(instParams.data() + nInstance, minInstances)...,
					std::forward<ChunkParams>(chunkParams[nChunk])...,
					std::forward<GlobalParams>(globalParams)...);
			}
		}

		template<typename... GlobalParams>
		OC_FORCEINLINE void setGlobalParams(GlobalParams&&... globalParams)
		{
			static_cast<Derived*>(this)->setParams(
				std::forward<GlobalParams>(globalParams)...);
		}

		template<typename... ChunkParams>
		OC_FORCEINLINE void runBatch2(
			Channel& chl, span<InstParams>... instParams,
			span<ChunkParams>... chunkParams)
		{
			size_t numInstances = checkSpanLengths(instParams..., chunkParams...).first;

			const size_t chunkSize = static_cast<const Derived*>(this)->chunkSize();
			const size_t minInstances = chunkSize + static_cast<Derived*>(this)->paddingSize();

			// The bulk of the instances can work directly on the input / output data.
			size_t nChunk = 0;
			size_t nInstance = 0;
			for (; nInstance + minInstances <= numInstances; ++nChunk, nInstance += chunkSize)
				static_cast<Derived*>(this)->processChunk(
					nChunk, chunkSize,
					span<InstParams>(instParams.data() + nInstance, minInstances)...,
					std::forward<ChunkParams>(chunkParams[nChunk])...);

			// The last few (probably only 1) need an intermediate buffer.
			for (; nInstance < numInstances; ++nChunk, nInstance += chunkSize)
			{
				size_t numUsed = std::min(numInstances - nInstance, chunkSize);
				processPartialChunk<ChunkParams...>(
					nChunk, numUsed, minInstances,
					span<InstParams>(instParams.data() + nInstance, minInstances)...,
					std::forward<ChunkParams>(chunkParams[nChunk])...);
			}
		}


		void initTemporaryStorage()
		{
			const size_t chunkSize = static_cast<const Derived*>(this)->chunkSize();
			const size_t minInstances = chunkSize + static_cast<Derived*>(this)->paddingSize();
			tempStorage = std::make_tuple(ChunkerAlloc<InstParamPtrs>::alloc(minInstances)...);
		}

		std::tuple<InstParamPtrs...> tempStorage;
	};

	// Sender refers to who will be sending mMessages, not to the OT sender. In fact, the OT receiver
	// will be the party sending mMessages in an IKNP-style OT extension.

	template<typename Derived, typename T, typename C = typename TupleOfUniquePtrs<T>::type>
	class ChunkedSender {};

	template<typename Derived, typename... InstParams, typename C>
	class ChunkedSender<Derived, std::tuple<InstParams...>, C> :
		public Chunker<Derived, std::tuple<InstParams...>, C>
	{
	protected:
		using Base = Chunker<Derived, std::tuple<InstParams...>, C>;
		using Base::checkSpanLengths;

		ChunkedSender(Derived* this_) : Base(this_) {}

	public:
		template<typename... ChunkParams, typename... GlobalParams>
		OC_FORCEINLINE void runBatch(
			Channel& chl, span<InstParams>... instParams,
			span<ChunkParams>... chunkParams, GlobalParams&&... globalParams)
		{
			auto nums = checkSpanLengths(instParams..., chunkParams...);
			size_t numInstances = nums.first;
			size_t numChunks = nums.second;

			const size_t chunkSize = static_cast<const Derived*>(this)->chunkSize();
			const size_t minInstances = chunkSize + static_cast<Derived*>(this)->paddingSize();
			static_cast<Derived*>(this)->reserveSendBuffer(std::min(numChunks, Derived::commSize));

			size_t nChunk = 0;
			size_t nInstance = 0;
			while (nInstance + minInstances <= numInstances)
			{
				static_cast<Derived*>(this)->processChunk(
					nChunk, chunkSize,
					span<InstParams>(instParams.data() + nInstance, minInstances)...,
					std::forward<ChunkParams>(chunkParams[nChunk])...,
					std::forward<GlobalParams>(globalParams)...);

				++nChunk;
				nInstance += chunkSize;
				if (nInstance + minInstances > numInstances)
					break;

				if (nChunk % Derived::commSize == 0)
				{
					static_cast<Derived*>(this)->sendBuffer(chl);
					static_cast<Derived*>(this)->
						reserveSendBuffer(std::min(numChunks - nChunk, Derived::commSize));
				}
			}

			for (; nInstance < numInstances; ++nChunk, nInstance += chunkSize)
			{
				if (nChunk % Derived::commSize == 0)
				{
					static_cast<Derived*>(this)->sendBuffer(chl);
					static_cast<Derived*>(this)->
						reserveSendBuffer(std::min(numChunks - nChunk, Derived::commSize));
				}

				size_t numUsed = std::min(numInstances - nInstance, chunkSize);
				Base::template processPartialChunk<ChunkParams...>(
					nChunk, numUsed, minInstances,
					span<InstParams>(instParams.data() + nInstance, minInstances)...,
					std::forward<ChunkParams>(chunkParams[nChunk])...,
					std::forward<GlobalParams>(globalParams)...);
			}

			static_cast<Derived*>(this)->sendBuffer(chl);
		}
	};

	template<typename Derived, typename T, typename C = typename TupleOfUniquePtrs<T>::type>
	class ChunkedReceiver {};

	template<typename Derived, typename... InstParams, typename C>
	class ChunkedReceiver<Derived, std::tuple<InstParams...>, C> :
		public Chunker<Derived, std::tuple<InstParams...>, C>
	{
	protected:
		using Base = Chunker<Derived, std::tuple<InstParams...>, C>;
		using Base::checkSpanLengths;

		ChunkedReceiver(Derived* this_) : Base(this_) {}

	public:
		template<typename... ChunkParams, typename... GlobalParams>
		OC_FORCEINLINE void runBatch(
			Channel& chl, span<InstParams>... instParams,
			span<ChunkParams>... chunkParams, GlobalParams&&... globalParams)
		{
			auto nums = checkSpanLengths(instParams..., chunkParams...);
			size_t numInstances = nums.first;
			size_t numChunks = nums.second;

			const size_t chunkSize = static_cast<const Derived*>(this)->chunkSize();
			const size_t minInstances = chunkSize + static_cast<Derived*>(this)->paddingSize();

			// The bulk of the instances can work directly on the input / output data.
			size_t nChunk = 0;
			size_t nInstance = 0;
			for (; nInstance + minInstances <= numInstances; ++nChunk, nInstance += chunkSize)
			{
				if (nChunk % Derived::commSize == 0)
					static_cast<Derived*>(this)->
					recvBuffer(chl, std::min(numChunks - nChunk, Derived::commSize));

				static_cast<Derived*>(this)->processChunk(
					nChunk, chunkSize,
					span<InstParams>(instParams.data() + nInstance, minInstances)...,
					std::forward<ChunkParams>(chunkParams[nChunk])...,
					std::forward<GlobalParams>(globalParams)...);
			}

			// The last few (probably only 1) need an intermediate buffer.
			for (; nInstance < numInstances; ++nChunk, nInstance += chunkSize)
			{
				if (nChunk % Derived::commSize == 0)
					static_cast<Derived*>(this)->
					recvBuffer(chl, std::min(numChunks - nChunk, Derived::commSize));

				size_t numUsed = std::min(numInstances - nInstance, chunkSize);
				Base::template processPartialChunk<ChunkParams...>(
					nChunk, numUsed, minInstances,
					span<InstParams>(instParams.data() + nInstance, minInstances)...,
					std::forward<ChunkParams>(chunkParams[nChunk])...,
					std::forward<GlobalParams>(globalParams)...);
			}
		}

	};

	template<typename Ptr>
	struct ChunkerAlloc {};

	//template<typename T>
	//struct ChunkerAlloc<std::unique_ptr<T[]>>
	//{
	//	static std::unique_ptr<T[]> alloc(size_t n)
	//	{
	//		return std::unique_ptr<T[]>(new T[n]);
	//	}
	//};

	template<typename T>
	struct ChunkerAlloc<AlignedUnVector<T>>
	{
		static AlignedUnVector<T> alloc(size_t n)
		{
			return AlignedUnVector<T>(n);
		}
	};

}
