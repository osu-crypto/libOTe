#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 

#include <string>
#include <memory>
#include <future>

#include "Common/Defines.h"

namespace osuCrypto {

    class Channel;  
    class Endpoint;

    /// <summary>Represents a possibly re-sizable buffer which a channel and read and write from.</summary>
    class ChannelBuffer
    {
    public:
        virtual ~ChannelBuffer()
        {
        }

    private:
        friend class Channel;
        friend class BtIOService;
        friend class BtChannel;
    protected:
        virtual u8* ChannelBufferData() const = 0;
        virtual u64 ChannelBufferSize() const = 0;
        virtual void ChannelBufferResize(u64 length) = 0;
    };

    /// <summary>Represents a named pipe that allows data to be send between two Endpoints</summary>
    class Channel
    {
    public:
        virtual ~Channel()
        {
        }

        /// <summary>Get the local endpoint for this channel.</summary>
        virtual Endpoint& getEndpoint()  = 0;

        /// <summary>The handle for this channel. Both ends will always have the same name.</summary>
        virtual std::string getName() const = 0;

        virtual void resetStats() {};

        virtual u64 getTotalDataSent() const = 0;

        virtual u64 getMaxOutstandingSendData() const = 0;

        /// <summary>Data will be sent over the network asynchronously. WARNING: data lifetime must be handled by caller.</summary>
        virtual void asyncSend(const void * bufferPtr, u64 length) = 0;

        /// <summary>Buffer will be MOVED and then sent over the network asynchronously. </summary>
        virtual void asyncSend(std::unique_ptr<ChannelBuffer> mH) = 0;

        /// <summary>Synchronous call to send data over the network. </summary>
        virtual void send(const void * bufferPtr, u64 length) = 0;

        /// <summary>A call to asynchronously receive data over this channel. Data will be saved at dest and is expected 
        ///          to be of size length. Will through otherwise</summary>
        virtual std::future<void> asyncRecv(void* dest, u64 length) = 0;

        /// <summary>A call to asynchronously receive data over this channel. Data will be saved at buff which will resized 
        /// (if allowed) to fit the data size.</summary>
        virtual std::future<void> asyncRecv(ChannelBuffer& mH) = 0;

        /// <summary>Synchronous call to receive data over the network. Assumes dest has byte size length. WARNING: will through if received message length does not match.</summary>
        virtual void recv(void* dest, u64 length) = 0; 

        /// <summary>Synchronous call to receive data over the network. Will *TRY* to resize buffer to be the appropriate size. A ChannelBuff may refuse to resize...</summary>
        virtual void recv(ChannelBuffer& mH) = 0;

        /// <summary>Returns whether this channel is open in that it can send/receive data</summary>
        virtual bool opened() = 0;

        /// <summary>A blocking call that waits until the channel is open in that it can send/receive data</summary>
        virtual void waitForOpen() = 0;

        /// <summary>Close this channel to denote that no more data will be sent or received.</summary>
        virtual void close() = 0;

        //
        // Helper functions.
        //

        /// <summary>Synchronous call to send data over the network. </summary>
        void send(const ChannelBuffer& buf);

        /// <summary>Performs a data copy and the returns. Data will be sent over the network asynconsouly. </summary>
        void asyncSendCopy(const ChannelBuffer& buf);

        /// <summary>Performs a data copy and the returns. Data will be sent over the network asynchronously.</summary> 
        void asyncSendCopy(const void * bufferPtr, u64 length);

    };

}