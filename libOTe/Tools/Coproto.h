#pragma once
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "coproto/coproto.h"
#include "macoro/macros.h"

#include "cryptoTools/Network/Channel.h"

namespace osuCrypto
{
	namespace cp = coproto;
	using coproto::task;
	using Socket = coproto::Socket;


#ifdef ENABLE_BOOST

	//struct CpChannel : public Socket
	//{
	//	struct CpAsyncChannelSock;

	//	struct Awaiter
	//	{
	//		CpAsyncChannelSock* mSock;
	//		span<u8> mData;
	//		bool mSend;
	//		macoro::stop_token mToken;

	//		Awaiter(CpAsyncChannelSock* sock, span<u8> data, bool send, macoro::stop_token&& token)
	//			: mSock(sock)
	//			, mData(data)
	//			, mSend(send)
	//			, mToken(std::move(token))
	//		{
	//		}

	//	};

	//	struct CpAsyncChannelSock 
	//	{

	//		CpAsyncChannelSock() = default;
	//		CpAsyncChannelSock(CpAsyncChannelSock&&) = delete;
	//		CpAsyncChannelSock(const CpAsyncChannelSock&) = delete;
	//		CpAsyncChannelSock(Channel& c) : mChl(c) {}
	//		Channel mChl;


	//		Awaiter send(span<u8> data, macoro::stop_token token = {}) { return Awaiter(this, data, true, std::move(token)); };
	//		Awaiter recv(span<u8> data, macoro::stop_token token = {}) { return Awaiter(this, data, false, std::move(token)); };

	//		//coproto::Continuation mSendCont, mRecvCont;
	//		//void send(coproto::span<u8> data2, coproto::Continuation&& cont) override
	//		//{
	//		//	span<u8>data = data2;
	//		//	auto s = data.size();

	//		//	assert(!mSendCont);
	//		//	mSendCont = std::move(cont);
	//		//	assert(mSendCont);
	//		//	mChl.asyncSend(std::move(data), [this, s](const error_code& ec) mutable {
	//		//		auto f = std::move(mSendCont);
	//		//		f(ec, ec ? 0 : s);
	//		//		});
	//		//}


	//		//span<u8> recvBuff;
	//		//void recv(coproto::span<u8> data, coproto::Continuation&& cont)
	//		//{
	//		//	recvBuff = data;
	//		//	assert(!mRecvCont);
	//		//	mRecvCont = std::move(cont);
	//		//	assert(mRecvCont);
	//		//	mChl.asyncRecv<span<u8>>((span<u8>&)recvBuff, [this](const error_code& ec)mutable {
	//		//		auto f = std::move(mRecvCont);
	//		//		f(ec, ec ? 0 : recvBuff.size());
	//		//		});
	//		//}

	//		//// Cancel any current operations. These operations 
	//		//// should retuen a error_code reflecting this. 
	//		//void cancel() override {
	//		//	mChl.cancel();
	//		//}
	//	};

	//	std::unique_ptr<CpAsyncChannelSock> mImpl;
	//	CpChannel() = default;
	//	CpChannel(CpChannel&&) = default;
	//	CpChannel& operator=(CpChannel&&) = default;

	//	CpChannel(Channel& c) : mImpl(new CpAsyncChannelSock(c)) {
	//		throw std::runtime_error(LOCATION);
	//		//static_cast<Socket&>(*this) = Socket(*mImpl);
	//	}

	//	CpChannel(Channel&& c) : mImpl(new CpAsyncChannelSock(c)) {
	//		throw std::runtime_error(LOCATION);
	//		//static_cast<Socket&>(*this) = Socket(*mImpl);
	//	}

	//};

#endif

}