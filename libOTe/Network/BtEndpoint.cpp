#include "BtEndpoint.h"
#include "Network/BtIOService.h"
#include "Network/BtChannel.h"
#include "Network/BtAcceptor.h"
#include "Common/ByteStream.h"
#include "Network/BtSocket.h"
#include "Common/Log.h"


#include <sstream>

namespace osuCrypto {

    //extern std::vector<std::string> split(const std::string &s, char delim);
        

    void BtEndpoint::start(BtIOService& ioService, std::string remoteIP, u32 port, bool host, std::string name)
    {
        if (mStopped == false)
            throw std::runtime_error("rt error at " LOCATION);


        mIP = (remoteIP);
        mPort = (port);
        mHost = (host);
        mIOService = &(ioService);
        mStopped = (false);
        mName = (name);

        if (host)
            mAcceptor = (ioService.getAcceptor(*this));
        else
        {
            boost::asio::ip::tcp::resolver resolver(mIOService->mIoService);
            boost::asio::ip::tcp::resolver::query query(remoteIP, boost::lexical_cast<std::string>(port));
            mRemoteAddr = *resolver.resolve(query);
        }

        std::lock_guard<std::mutex> lock(ioService.mMtx);
        ioService.mEndpointStopFutures.push_back(mDoneFuture);

    }

    void BtEndpoint::start(BtIOService& ioService, std::string address, bool host, std::string name)
    {
        auto vec = split(address, ':');

        auto ip = vec[0];
        auto port = 1212;
        if (vec.size() > 1)
        {
            std::stringstream ss(vec[1]);
            ss >> port;
        } 

        start(ioService, ip, port, host, name);

    }

    BtEndpoint::~BtEndpoint()
    {
    }

    std::string BtEndpoint::getName() const
    {
        return mName;
    }


    Channel & BtEndpoint::addChannel(std::string localName, std::string remoteName)
    {

        BtChannel* chlPtr;

        // first, add the channel to the endpoint.
        {
            std::lock_guard<std::mutex> lock(mAddChannelMtx);

            if (mStopped == true)
            {
                throw std::runtime_error("rt error at " LOCATION);
            }

            mChannels.emplace_back(*this, localName, remoteName);
            chlPtr = &mChannels.back();
        }

        BtChannel& chl = *chlPtr;


        if (mHost)
        {
            // if we are a host, then we can ask out acceptor for the socket which match the channel name.
            chl.mSocket.reset(mAcceptor->getSocket(chl));
        }
        else
        {
            chl.mSocket.reset(new BtSocket(*mIOService));

            boost::system::error_code ec;
            auto tryCount = 10000000;

            chl.mSocket->mHandle.connect(mRemoteAddr, ec);

            while (tryCount-- && ec)
            {
                chl.mSocket->mHandle.connect(mRemoteAddr, ec);
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }

            if (ec)
            {
                throw std::runtime_error("rt error at " LOCATION);
            }

            boost::asio::ip::tcp::no_delay option(true);
            chl.mSocket->mHandle.set_option(option);

            //boost::asio::socket_base::receive_buffer_size option2((1 << 20) * 16);
            //chl.mSocket->mHandle.set_option(option2);

            //boost::asio::socket_base::send_buffer_size option3((1 << 20) * 16);
            ////chl.mSocket->mHandle.set_option(option3);

            std::stringstream ss;
            ss << mName << char('`') << localName << char('`') << remoteName;

            auto str = ss.str();
            std::unique_ptr<ByteStream> buff(new ByteStream((u8*)str.data(), str.size()));


            chl.asyncSend(std::move(buff));
        }

        return chl;
    }


    void BtEndpoint::stop()
    {
        {
            std::lock_guard<std::mutex> lock(mAddChannelMtx);
            if (mStopped == false)
            {
                mStopped = true;

                if (mChannels.size() == 0)
                {
                    mDoneProm.set_value();
                }
            }
        }
        mDoneFuture.get();
    }

    bool BtEndpoint::stopped() const
    {
        return mStopped;
    }

    void BtEndpoint::removeChannel(std::string  chlName)
    {
        std::lock_guard<std::mutex> lock(mAddChannelMtx);

        auto iter = mChannels.begin();

        while (iter != mChannels.end())
        {
            auto name = iter->getName();
            if (name == chlName)
            {
                //Log::out << Log::lock << "removing " << getName() << " "<< name << " = " << chlName << Log::unlock << Log::endl;
                mChannels.erase(iter);
                break;
            }
            ++iter;
        }

        // if there are no more channels and the send point has stopped, signal that the last one was just removed.
        if (mStopped && mChannels.size() == 0)
        {
            mDoneProm.set_value();
        }
    }
}
