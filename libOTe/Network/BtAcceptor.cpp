#include "Network/BtAcceptor.h"
#include "Network/BtIOService.h"
#include "Network/BtChannel.h"
#include "Network/Endpoint.h"
#include "Common/Log.h"
#include <Common/ByteStream.h>

#include "boost/lexical_cast.hpp"

namespace osuCrypto {


    BtAcceptor::BtAcceptor(BtIOService& ioService)
        :
        mStoppedFuture(mStoppedPromise.get_future()),
        mIOService(ioService),
        mHandle(ioService.mIoService),
        mStopped(false),
        mPort(0)
    {
        mStopped = false;


    }



    BtAcceptor::~BtAcceptor()
    {
        stop();


        mStoppedFuture.get();
    }




    void BtAcceptor::bind(u32 port, std::string ip)
    {
        auto pStr = std::to_string(port);
        mPort = port;

        boost::asio::ip::tcp::resolver resolver(mIOService.mIoService);
        boost::asio::ip::tcp::resolver::query
            query(ip, pStr);

        mAddress = *resolver.resolve(query);

        mHandle.open(mAddress.protocol());
        mHandle.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));

        boost::system::error_code ec;
        mHandle.bind(mAddress, ec);

        if (mAddress.port() != port)
            throw std::runtime_error("rt error at " LOCATION);

        if(ec)
        {
            Log::out << ec.message() << Log::endl;

            throw std::runtime_error(ec.message());
        }


        mHandle.listen(boost::asio::socket_base::max_connections);
    }

    void BtAcceptor::start() 
    {
        if (stopped() == false)
        {

            BtSocket* newSocket = new BtSocket(mIOService);
            mHandle.async_accept(newSocket->mHandle, [newSocket, this](const boost::system::error_code& ec)
            {
                start();

                if (!ec)
                {

                    auto buff = new ByteStream(4);
                    buff->setp(buff->capacity());

                    boost::asio::ip::tcp::no_delay option(true);
                    newSocket->mHandle.set_option(option);

                    //boost::asio::socket_base::receive_buffer_size option2(262144);
                    //newSocket->mHandle.set_option(option2);
                    //newSocket->mHandle.get_option(option2);
                    //Log::out << option2.value() << Log::endl;


                    //boost::asio::socket_base::send_buffer_size option3((1 << 20 )/8);
                    //newSocket->mHandle.set_option(option3);
                    //newSocket->mHandle.get_option(option3);
                    //Log::out << option3.value() << Log::endl;

                    newSocket->mHandle.async_receive(boost::asio::buffer(buff->data(), buff->size()), 
                        [newSocket, buff, this](const boost::system::error_code& ec2, u64 bytesTransferred)
                    {
                        if(!ec2 || bytesTransferred != 4)
                        {
                            u32 size = buff->getArrayView<u32>()[0];

                            buff->reserve(size);
                            buff->setp(size);

                            newSocket->mHandle.async_receive(boost::asio::buffer(buff->data(), buff->size()),
                                [newSocket, buff, size, this](const boost::system::error_code& ec3, u64 bytesTransferred2)
                            {
                                if (!ec3 || bytesTransferred2 != size)
                                {
                                    // lets split it into pieces.
                                    auto names = split(std::string((char*)buff->data(), buff->size()), char('`'));


                                    // Now lets create or get the std::promise<WinNetSocket> that will hold this socket
                                    // for the WinNetEndpoint that will eventually receive it.
                                    auto& prom = getSocketPromise(names[0], names[2], names[1]);


                                    prom.set_value(newSocket);
                                }
                                else
                                {
                                    Log::out << "async_accept->async_receive->async_receive (body) failed with error_code:" << ec3.message() << Log::endl;
                                }

                                delete buff;
                            });

                        }
                        else
                        {
                            Log::out << "async_accept->async_receive (header) failed with error_code:" << ec2.message() << Log::endl;
                            delete newSocket;
                            delete buff;
                        }

                    });
                }
                else
                {
                    //Log::out << "async_accept failed with error_code:" << ec.message() << Log::endl;
                    delete newSocket;
                }
            });
        }
        else
        {
            mStoppedPromise.set_value();
        }
    }

    void BtAcceptor::stop()
    {
        mStopped = true;
        mHandle.close();
    }

    bool BtAcceptor::stopped() const
    {
        return mStopped;
    }

    BtSocket* BtAcceptor::getSocket(BtChannel & chl)
    {
        std::string tag = chl.getEndpoint().getName() + ":" + chl.getName() + ":" + chl.getRemoteName();

        {
            std::unique_lock<std::mutex> lock(mMtx);
            auto iter = mSocketPromises.find(tag);

            if (iter == mSocketPromises.end())
            {
                mSocketPromises.emplace(tag, std::promise<BtSocket*>());
            }
        }
        return std::move(mSocketPromises[tag].get_future().get());
    }

    std::promise<BtSocket*>& BtAcceptor::getSocketPromise(
        std::string endpointName,
        std::string localChannelName,
        std::string remoteChannelName)
    {
        std::string tag = endpointName + ":" + localChannelName + ":" + remoteChannelName;

        {
            std::unique_lock<std::mutex> lock(mMtx);
            auto iter = mSocketPromises.find(tag);

            if (iter == mSocketPromises.end())
            {
                mSocketPromises.emplace(tag, std::promise<BtSocket*>());
            }
        }

        return mSocketPromises[tag];
    }
}
