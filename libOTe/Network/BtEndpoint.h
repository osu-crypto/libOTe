#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.  
#include "Common/Defines.h"

#include "BtAcceptor.h"
#include "Network/Endpoint.h"
#include "Network/BtChannel.h"
#include "Network/BtIOService.h"
#include <list>
#include <mutex>

#include "boost/lexical_cast.hpp"

namespace osuCrypto {


    class BtAcceptor;

    class BtEndpoint :
        public Endpoint
    { 

        BtEndpoint(const BtEndpoint&) = delete;

        std::string mIP;
        u32 mPort;
        bool mHost, mStopped;
        BtIOService* mIOService;
        BtAcceptor* mAcceptor;
        std::list<BtChannel> mChannels;
        std::mutex mAddChannelMtx; 
        std::promise<void> mDoneProm;
        std::shared_future<void> mDoneFuture;
        std::string mName;
        boost::asio::ip::tcp::endpoint mRemoteAddr;
    public:

        void start(BtIOService& ioService, std::string remoteIp, u32 port, bool host, std::string name);
        void start(BtIOService& ioService, std::string address, bool host, std::string name);

        BtEndpoint(BtIOService & ioService, std::string address, bool host, std::string name)
            : mPort(0), mHost(false), mStopped(true), mIOService(nullptr), mAcceptor(nullptr),
            mDoneFuture(mDoneProm.get_future().share())
        {
            start(ioService, address, host, name);
        }

        BtEndpoint(BtIOService & ioService, std::string remoteIP, u32 port, bool host, std::string name)
            : mPort(0), mHost(false), mStopped(true), mIOService(nullptr), mAcceptor(nullptr),
            mDoneFuture(mDoneProm.get_future().share())
        {
            start(ioService, remoteIP, port, host, name);
        }


        BtEndpoint()
            : mPort(0), mHost(false), mStopped(true), mIOService(nullptr), mAcceptor(nullptr),
              mDoneFuture(mDoneProm.get_future().share())
        {
        }

        ~BtEndpoint();

        std::string getName() const override;

        BtIOService& getIOService() { return *mIOService; }

        /// <summary>Adds a new channel (data pipe) between this endpoint and the remote. The channel is named at each end.</summary>
        Channel& addChannel(std::string localName, std::string remoteName) override;


        /// <summary>Stops this Endpoint. Will block until all channels have closed.</summary>
        void stop() override;

        /// <summary>returns whether the endpoint has been stopped (or never opened).</summary>
        bool stopped() const override;

        /// <summary> Removes the channel with chlName. (deallocates it)</summary>
        void removeChannel(std::string  chlName);

        u32 port() const { return mPort; };

        std::string IP() const { return mIP;  }

        bool isHost() const { return mHost; };
    };


}