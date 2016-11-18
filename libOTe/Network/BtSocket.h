#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include "Common/Defines.h"


#include <deque>
#include <mutex>
#include <future> 

#include "Network/BtIOService.h"

namespace osuCrypto { 

    class WinNetIOService;
    class ChannelBuffer;


    struct BoostIOOperation
    {
        enum class Type
        {
            RecvName,
            RecvData,
            CloseRecv,
            SendData,
            CloseSend,
            CloseThread
        };

        BoostIOOperation()
        {
            clear();
        }

        BoostIOOperation(const BoostIOOperation& copy)
        {
            mType = copy.mType;
            mSize = copy.mSize;
            mBuffs[0] = boost::asio::buffer(&mSize, sizeof(u32));
            mBuffs[1] = copy.mBuffs[1];
            mOther = copy.mOther;
            mPromise = copy.mPromise;
        }

        void clear()
        {
            mType = (Type)0;
            mSize = 0; 
            mBuffs[0] = boost::asio::buffer(&mSize, sizeof(u32));
            mBuffs[1] = boost::asio::mutable_buffer();
            mOther = nullptr;
            mPromise = nullptr;
        } 


        std::array<boost::asio::mutable_buffer,2> mBuffs;
        Type mType;
        u32 mSize;

        void* mOther;
        std::promise<void>* mPromise;
        std::exception_ptr mException;
        //std::function<void()> mCallback;
    };



    class BtSocket
    {
    public:
        BtSocket(BtIOService& ios);

        boost::asio::ip::tcp::socket mHandle;
        boost::asio::strand mSendStrand, mRecvStrand;

        std::deque<BoostIOOperation> mSendQueue, mRecvQueue;
        bool mStopped;

        std::atomic<u64> mOutstandingSendData, mMaxOutstandingSendData, mTotalSentData;
    };

    inline BtSocket::BtSocket(BtIOService& ios) :
        mHandle(ios.mIoService),
        mSendStrand(ios.mIoService),
        mRecvStrand(ios.mIoService),
        mStopped(false),
        mOutstandingSendData(0),
        mMaxOutstandingSendData(0),
        mTotalSentData(0)
    {}


}
