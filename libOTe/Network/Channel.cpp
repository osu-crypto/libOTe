#include "Channel.h"
#include "Common/ByteStream.h"

void osuCrypto::Channel::send(const ChannelBuffer & buf)
{
    send(buf.ChannelBufferData(), buf.ChannelBufferSize());
}

void osuCrypto::Channel::asyncSendCopy(const ChannelBuffer & buf)
{
    asyncSendCopy(buf.ChannelBufferData(), buf.ChannelBufferSize());
}

void osuCrypto::Channel::asyncSendCopy(const void * bufferPtr, u64 length)
{
    std::unique_ptr<ByteStream> bs(new ByteStream((u8*)bufferPtr, length));
    asyncSend(std::move(bs));
}
