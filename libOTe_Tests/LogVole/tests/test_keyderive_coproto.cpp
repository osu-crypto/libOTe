#include "libOTe/Vole/LogVole/LogVoleRingReceiver.h"
#include "libOTe/Vole/LogVole/LogVoleRingSender.h"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include "coproto/Socket/LocalAsyncSock.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"

#include <cstddef>
#include <cstdint>
#include <array>
#include <stdexcept>
#include <tuple>
#include <vector>

using namespace osuCrypto::LogVole;

namespace
{
    RingParams make_params()
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        assignValues<int>(params.mCoeffModulusBits, { 30, 30 });
        return params;
    }

    std::vector<RnsPoly> sample_batch(
        const RingNttContext& ctx,
        std::uint32_t count,
        std::uint64_t seed)
    {
        std::vector<RnsPoly> out;
        out.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i)
        {
            out.push_back(deriveUniformPolyFromNonce(ctx, seed, 0x4B4452495645u, i));
        }
        return out;
    }

    void expect_poly_equal(const RnsPoly& a, const RnsPoly& b)
    {
        LOGVOLE_REQUIRE_EQ(a.mCoeffs.size(), b.mCoeffs.size());
        for (std::size_t i = 0; i < a.mCoeffs.size(); ++i)
        {
            LOGVOLE_EXPECT_EQ(a.mCoeffs[i], b.mCoeffs[i]) << "coeff idx " << i;
        }
    }

    void expect_batch_equal(const std::vector<RnsPoly>& a, const std::vector<RnsPoly>& b)
    {
        LOGVOLE_REQUIRE_EQ(a.size(), b.size());
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            expect_poly_equal(a[i], b[i]);
        }
    }

    void run_coproto_case(std::uint64_t seed, std::uint32_t tau)
    {
        const auto params = make_params();
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

        KeyDeriveSenderInput senderInput{};
        senderInput.mParams = params;
        senderInput.mSk1 = sample_batch(ctx, tau, seed + 1u);
        senderInput.mSk2 = sample_batch(ctx, tau, seed + 2u);

        KeyDeriveReceiverInput receiverInput{};
        receiverInput.mParams = params;
        receiverInput.mD = sample_batch(ctx, tau, seed + 3u);

        LogVoleRingSender sender{};
        LogVoleRingReceiver receiver{};
        KeyDeriveSenderOutput senderOutput{};
        KeyDeriveReceiverOutput receiverOutput{};

        auto sockets = coproto::LocalAsyncSocket::makePair();
        auto result = macoro::sync_wait(macoro::when_all_ready(
            sender.keyDerive(senderInput, senderOutput, sockets[0]),
            receiver.keyDerive(receiverInput, receiverOutput, sockets[1])));
        std::get<0>(result).result();
        std::get<1>(result).result();

        expect_batch_equal(senderOutput.mK, senderInput.mSk2);
        LOGVOLE_REQUIRE_EQ(receiverOutput.mM.size(), receiverInput.mD.size());

        for (std::size_t i = 0; i < receiverInput.mD.size(); ++i)
        {
            RnsPoly product{};
            LOGVOLE_REQUIRE_TRUE(ringMultiply(senderInput.mSk1[i], receiverInput.mD[i], ctx, product));

            RnsPoly expected{};
            LOGVOLE_REQUIRE_TRUE(ringAdd(product, senderInput.mSk2[i], ctx, expected));

            expect_poly_equal(receiverOutput.mM[i], expected);
        }
    }

	void write_u64(std::array<std::uint8_t, sizeof(std::uint64_t)>& out, std::uint64_t value)
	{
		for (std::size_t i = 0; i < out.size(); ++i)
			out[i] = static_cast<std::uint8_t>(value >> (8u * i));
	}

	std::uint64_t read_u64(const std::array<std::uint8_t, sizeof(std::uint64_t)>& in)
	{
		std::uint64_t value = 0;
		for (std::size_t i = 0; i < in.size(); ++i)
			value |= static_cast<std::uint64_t>(in[i]) << (8u * i);
		return value;
	}

	macoro::task<> send_oversized_frame(
		coproto::Socket& sock,
		std::uint64_t payloadSize,
		bool drainRequest)
	{
		if (drainRequest)
		{
			std::array<std::uint8_t, sizeof(std::uint64_t)> requestHeader{};
			co_await sock.recv(requestHeader);
			Buffer request(static_cast<std::size_t>(read_u64(requestHeader)));
			if (!request.empty())
				co_await sock.recv(request);
		}

		std::array<std::uint8_t, sizeof(std::uint64_t)> header{};
		write_u64(header, payloadSize);
		co_await sock.send(coproto::copy(header));
	}

	template<typename ProtocolTask, typename PeerTask>
	void expect_length_rejection(ProtocolTask protocol, PeerTask peer)
	{
		auto result = macoro::sync_wait(macoro::when_all_ready(std::move(protocol), std::move(peer)));
		bool rejectedLength = false;
		try
		{
			std::get<0>(result).result();
		}
		catch (const std::length_error&)
		{
			rejectedLength = true;
		}
		std::get<1>(result).result();
		LOGVOLE_EXPECT_TRUE(rejectedLength);
	}
}

void LogVole_KeyDeriveCoproto_HappyPathAndAlgebraicRelation(const oc::CLP&)
{
    run_coproto_case(0x1110u, 3);
}

void LogVole_KeyDeriveCoproto_DeterministicRegressionSeeds(const oc::CLP&)
{
    for (const auto seed : { 0x10u, 0x20u, 0x30u, 0x40u })
    {
        run_coproto_case(seed, 2);
    }
}

void LogVole_KeyDeriveCoproto_OversizedFramesRejectedBeforeAllocation(const oc::CLP&)
{
	const auto params = make_params();
	RingNttContext ctx{};
	LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
	constexpr std::uint32_t tau = 3;
	std::uint64_t expectedSize = 0;
	LOGVOLE_REQUIRE_TRUE(keyDerivePayloadSize(params, tau, expectedSize));
	LOGVOLE_REQUIRE_LT(expectedSize, 1u << 20);

	KeyDeriveSenderInput senderInput{};
	senderInput.mParams = params;
	senderInput.mSk1 = sample_batch(ctx, tau, 0x7101u);
	senderInput.mSk2 = sample_batch(ctx, tau, 0x7102u);
	KeyDeriveSenderOutput senderOutput{};
	LogVoleRingSender sender{};
	auto senderSockets = coproto::LocalAsyncSocket::makePair();
	expect_length_rejection(
		sender.keyDerive(senderInput, senderOutput, senderSockets[0]),
		send_oversized_frame(senderSockets[1], expectedSize + 1u, false));

	KeyDeriveReceiverInput receiverInput{};
	receiverInput.mParams = params;
	receiverInput.mD = sample_batch(ctx, tau, 0x7201u);
	KeyDeriveReceiverOutput receiverOutput{};
	LogVoleRingReceiver receiver{};
	auto receiverSockets = coproto::LocalAsyncSocket::makePair();
	expect_length_rejection(
		receiver.keyDerive(receiverInput, receiverOutput, receiverSockets[0]),
		send_oversized_frame(receiverSockets[1], expectedSize + 1u, true));
}
