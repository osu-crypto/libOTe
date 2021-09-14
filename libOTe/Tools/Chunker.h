#pragma once
#include <libOTe/config.h>

#include <algorithm>
#include <memory>
#include <tuple>
#include <type_traits>
#include <utility>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <boost/mp11/tuple.hpp>

namespace osuCrypto
{

// TODO: Parallelization should probably be implemented here somewhere.

// Required definitions inside any class inheriting from Chunker:
/*
// Number of instances that are done at once.
static const size_t chunkSize;

// All spans will have the same size: chunkSize + paddingSize. numUsed is the number (<=
// chunkSize) of instances that will actually be used, out of the chunkSize instances.
// chunkParams are parameters that are given once per chunk, and globalParams are given once for
// the whole batch. This doesn't have to be defined for all template parameter. The template
// parameters just illustrate the class of functions that are be allowed.
template<typename... ChunkParams, typename... GlobalParams>
void processChunk(size_t numUsed, span<InstParams>... instParams,
                  ChunkParams... chunkParams, GlobalParams... globalParams);

// Number of instances worth of extra data that it should be allowed to read/write, above the
// chunkSize instances that are actually used.
size_t paddingSize() const;
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
// parameters of runBatch. InstParams is wrapped in a tuple<>, to encode a variadic in a type.

template<
	typename Derived,
	typename T,
	typename I = std::make_index_sequence<std::tuple_size<T>::value>
>
class Chunker {};

// Partial specialization to get access to the parameter packs.
template<
	typename Derived,
	typename... InstParams,
	size_t... InstIndices
>
class Chunker<
	Derived,
	std::tuple<InstParams...>,
	std::integer_sequence<size_t, InstIndices...>>
{
protected:
	// Derved* forces correct inheritance (https://stackoverflow.com/a/4418038/4071916)
	Chunker(Derived* this_) {}

public:
	using InstanceParams = std::tuple<InstParams...>;

	// Use temporaries to make processChunk work on a partial chunk.
	template<typename... ChunkParams, typename... GlobalParams>
	TRY_FORCEINLINE void processPartialChunk(
		size_t numUsed, size_t minInstances, span<InstParams>... instParams,
		ChunkParams... chunkParams, GlobalParams&&... globalParams)
	{
		// Copy the data into the temporaries. tuple_transform requires a non-void return type.
		using boost::mp11::tuple_transform;
		tuple_transform(
			[=](auto in, const auto& out) { std::copy_n(in, numUsed, out.get()); return 0; },
			std::make_tuple(instParams.data()...), tempStorage);

		static_cast<Derived*>(this)->processChunk(
			numUsed, span<InstParams>(std::get<InstIndices>(tempStorage).get(), minInstances)...,
			std::forward<ChunkParams>(chunkParams)...,
			std::forward<GlobalParams>(globalParams)...);

		// And copy it back out again. The compiler should hopefully be smart enough to remove
		// the first copy if processChunk is write only. (TODO: check).
		tuple_transform(CopyOutFunc{numUsed}, tempStorage,
			std::make_tuple(instParams.data()...));
	}

	// Helper to copy to a pointer unless it points to const.
	struct CopyOutFunc
	{
		size_t n;

		template<typename T, typename U>
		int operator()(const T& in, const U* out) const { return 0; }
		template<typename T, typename U>
		int operator()(const T& in, U* out) const { std::copy_n(in.get(), n, out); return 0; }
	};

	template<typename... ChunkParams>
	std::pair<size_t, size_t>
	checkSpanLengths(span<InstParams>... instParams, span<ChunkParams>... chunkParams) const
	{
		size_t numInstancesArray[] = { (size_t) instParams.size()... };
		size_t numInstances = numInstancesArray[0];
		for (size_t n : numInstancesArray)
			if (n != numInstances)
				throw RTE_LOC;

		size_t numChunks = divCeil(numInstances, Derived::chunkSize);
		size_t numChunksArray[] = { (size_t) chunkParams.size()... };
		for (size_t n : numChunksArray)
			if (n != numChunks)
				throw RTE_LOC;

		return std::pair<size_t, size_t>(numInstances, numChunks);
	}

	template<typename... ChunkParams, typename... GlobalParams>
	TRY_FORCEINLINE void runBatch(
		Channel& chl, span<InstParams>... instParams,
		span<ChunkParams>... chunkParams, GlobalParams&&... globalParams)
	{
		size_t numInstances = checkSpanLengths(instParams..., chunkParams...).first;

		const size_t minInstances = Derived::chunkSize + static_cast<Derived*>(this)->paddingSize();

		// The bulk of the instances can work directly on the input / output data.
		size_t nChunk = 0;
		size_t nInstance = 0;
		for (; nInstance + minInstances <= numInstances; ++nChunk, nInstance += Derived::chunkSize)
			static_cast<Derived*>(this)->processChunk(
				Derived::chunkSize, span<InstParams>(instParams.data() + nInstance, minInstances)...,
				std::forward<ChunkParams>(chunkParams[nChunk])...,
				std::forward<GlobalParams>(globalParams)...);

		// The last few (probably only 1) need an intermediate buffer.
		for (; nInstance < numInstances; ++nChunk, nInstance += Derived::chunkSize)
		{
			size_t numUsed = std::min(numInstances - nInstance, Derived::chunkSize);
			processPartialChunk<ChunkParams...>(
				numUsed, minInstances,
				span<InstParams>(instParams.data() + nInstance, minInstances)...,
				std::forward<ChunkParams>(chunkParams[nChunk])...,
				std::forward<GlobalParams>(globalParams)...);
		}
	}

	void initTemporaryStorage()
	{
		const size_t minInstances = Derived::chunkSize + static_cast<Derived*>(this)->paddingSize();
		tempStorage = std::make_tuple(
			std::make_unique<typename std::remove_const<InstParams>::type[]>(minInstances)...);
	}

	std::tuple<std::unique_ptr<typename std::remove_const<InstParams>::type[]>...> tempStorage;
};

// Sender refers to who will be sending messages, not to the OT sender. In fact, the OT receiver
// will be the party sending messages in an IKNP-style OT extension.

template<typename Derived, typename T>
class ChunkedSender {};

template<typename Derived, typename... InstParams>
class ChunkedSender<Derived, std::tuple<InstParams...>> :
	public Chunker<Derived, std::tuple<InstParams...>>
{
protected:
	using Base = Chunker<Derived, std::tuple<InstParams...>>;
	using Base::checkSpanLengths;

	ChunkedSender(Derived* this_) : Base(this_) {}

public:
	template<typename... ChunkParams, typename... GlobalParams>
	TRY_FORCEINLINE void runBatch(
		Channel& chl, span<InstParams>... instParams,
		span<ChunkParams>... chunkParams, GlobalParams&&... globalParams)
	{
		auto nums = checkSpanLengths(instParams..., chunkParams...);
		size_t numInstances = nums.first;
		size_t numChunks = nums.second;

		const size_t minInstances = Derived::chunkSize + static_cast<Derived*>(this)->paddingSize();
		static_cast<Derived*>(this)->reserveSendBuffer(std::min(numChunks, Derived::commSize));

		size_t nChunk = 0;
		size_t nInstance = 0;
		while (nInstance + minInstances <= numInstances)
		{
			static_cast<Derived*>(this)->processChunk(
				Derived::chunkSize, span<InstParams>(instParams.data() + nInstance, minInstances)...,
				std::forward<ChunkParams>(chunkParams[nChunk])...,
				std::forward<GlobalParams>(globalParams)...);

			++nChunk;
			nInstance += Derived::chunkSize;
			if (nInstance + minInstances > numInstances)
				break;

			if (nChunk % Derived::commSize == 0)
			{
				static_cast<Derived*>(this)->sendBuffer(chl);
				static_cast<Derived*>(this)->
					reserveSendBuffer(std::min(numChunks - nChunk, Derived::commSize));
			}
		}

		for (; nInstance < numInstances; ++nChunk, nInstance += Derived::chunkSize)
		{
			if (nChunk % Derived::commSize == 0)
			{
				static_cast<Derived*>(this)->sendBuffer(chl);
				static_cast<Derived*>(this)->
					reserveSendBuffer(std::min(numChunks - nChunk, Derived::commSize));
			}

			size_t numUsed = std::min(numInstances - nInstance, Derived::chunkSize);
			Base::template processPartialChunk<ChunkParams...>(
				numUsed, minInstances,
				span<InstParams>(instParams.data() + nInstance, minInstances)...,
				std::forward<ChunkParams>(chunkParams[nChunk])...,
				std::forward<GlobalParams>(globalParams)...);
		}

		static_cast<Derived*>(this)->sendBuffer(chl);
	}
};

template<typename Derived, typename T>
class ChunkedReceiver {};

template<typename Derived, typename... InstParams>
class ChunkedReceiver<Derived, std::tuple<InstParams...>> :
	public Chunker<Derived, std::tuple<InstParams...>>
{
protected:
	using Base = Chunker<Derived, std::tuple<InstParams...>>;
	using Base::checkSpanLengths;

	ChunkedReceiver(Derived* this_) : Base(this_) {}

public:
	template<typename... ChunkParams, typename... GlobalParams>
	TRY_FORCEINLINE void runBatch(
		Channel& chl, span<InstParams>... instParams,
		span<ChunkParams>... chunkParams, GlobalParams&&... globalParams)
	{
		auto nums = checkSpanLengths(instParams..., chunkParams...);
		size_t numInstances = nums.first;
		size_t numChunks = nums.second;

		const size_t minInstances = Derived::chunkSize + static_cast<Derived*>(this)->paddingSize();

		// The bulk of the instances can work directly on the input / output data.
		size_t nChunk = 0;
		size_t nInstance = 0;
		for (; nInstance + minInstances <= numInstances; ++nChunk, nInstance += Derived::chunkSize)
		{
			if (nChunk % Derived::commSize == 0)
				static_cast<Derived*>(this)->
					recvBuffer(chl, std::min(numChunks - nChunk, Derived::commSize));

			static_cast<Derived*>(this)->processChunk(
				Derived::chunkSize, span<InstParams>(instParams.data() + nInstance, minInstances)...,
				std::forward<ChunkParams>(chunkParams[nChunk])...,
				std::forward<GlobalParams>(globalParams)...);
		}

		// The last few (probably only 1) need an intermediate buffer.
		for (; nInstance < numInstances; ++nChunk, nInstance += Derived::chunkSize)
		{
			if (nChunk % Derived::commSize == 0)
				static_cast<Derived*>(this)->
					recvBuffer(chl, std::min(numChunks - nChunk, Derived::commSize));

			size_t numUsed = std::min(numInstances - nInstance, Derived::chunkSize);
			Base::template processPartialChunk<ChunkParams...>(
				numUsed, minInstances,
				span<InstParams>(instParams.data() + nInstance, minInstances)...,
				std::forward<ChunkParams>(chunkParams[nChunk])...,
				std::forward<GlobalParams>(globalParams)...);
		}
	}
};

}
