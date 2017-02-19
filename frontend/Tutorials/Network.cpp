#include "Network.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/BtIOService.h>


using namespace osuCrypto;

void networkTutorial()
{

    /*#####################################################
    ##                      Setup                        ##
    #####################################################*/

    // create network I/O service with 4 background threads. 
    // This object must stay in scope until everything is cleaned up.
    BtIOService ios(4);

    std::string serversIpAddress = "127.0.0.1:1212";


    // Network fully supports the multi party setting. A single
    // server can connect to many clients with a single port.
    // This is mannaged with connection names.
    std::string connectionName = "party0_party1";


    // connectionName denotes an identifier that both people on either side 
    // of this connection will use. If a server connects to several clients,
    // they should all use different connection names.
    BtEndpoint server(ios, serversIpAddress, /*is server?*/ true, connectionName);
    BtEndpoint client(ios, serversIpAddress, /*is server?*/ false, connectionName);


    // Two endpoints with the same connectionName can have many channels, each independent.
    // To support that, each channel pair will have a unique name.
    std::string channelName = "channelName";

    // Actually get the channel that can be used to communicate on.
    Channel& chl0 = client.addChannel(channelName);

    Channel& chl1 = server.addChannel(channelName);


    /*#####################################################
    ##                   The Basics                      ##
    #####################################################*/

    // There are several ways and modes to send and receive data.
    // The simplest mode is block, i.e. when data is sent, the caller
    // blocks until all data is sent.

    // For example:
    {
        std::vector<int> data{ 0,1,2,3,4,5,6,7 };
        chl0.send(data);


        std::vector<int> dest;
        chl1.recv(dest);
    }


    // It is now the case that data == dest. When data is received,
    // the Channel will call dest.resize(8)
    
    // In the example above, 
    // the Channel can tell that data is an STL like container. 
    // That is, it has member functions and types:
    //
    //   Container<T>::data() -> Container<T>::pointer
    //   Container<T>::size() -> Container<T>::size_type
    //   Container<T>::value_type
    //
    // Anything with these traits can be used, e.g. std::array<T,N>.
    {
        std::array<int, 4> data{ 0,1,2,3 };
        chl0.send(data);

        std::array<int, 4> dest;
        chl1.recv(dest);
    }

    // You can also use a pointer and length to send and receive data.
    // In the case that the data being recieved is the wrong size,
    // Channel::recv(...) will throw.
    {
        std::array<int, 4> data{ 0,1,2,3 };
        chl0.send(data.data(), data.size());


        std::array<int, 4> dest;
        chl1.recv(dest.data(), dest.size()); // may throw
    }

    // One issue with this approach is that the call 
    //
    //        chl0.send(...);
    //
    // blocks until all of the data has been sent over the network. If data 
    // is large, or if we send amny things, then this may take awhile.



    /*#####################################################
    ##                  Asynchronous                     ##
    #####################################################*/

    // We can overcome this with Asynchronous IO. These calls do not block.
    // In this example, note that std::move semantics are used.
    {
        std::vector<int> data{ 0,1,2,3,4,5,6,7 };
        chl0.asyncSend(std::move(data)); // will not block.


        std::vector<int> dest;
        chl1.recv(dest); // will block.
    }

    // the call
    //
    //  Channel::asyncSend(...);
    //
    // does not block. Instead, it "steals" the data contained inside
    // the vector. As a result, data is empty after this call.
    
    // When move semantics are not supported by Container or if you want to
    // share ownership of the data, we can use a unique/shared pointer. 
    {
        std::unique_ptr<std::array<int, 8>> unique{ new std::array<int,8>{0,1,2,3,4,5,6,7 } };
        chl0.asyncSend(std::move(unique)); // will not block.

        // unique = empty

        std::shared_ptr<std::array<int, 8>> shared{ new std::array<int,8>{0,1,2,3,4,5,6,7 } };
        chl0.asyncSend(std::move(shared)); // will not block.

        // shared's refernce counter = 2.

        std::vector<int> dest;
        chl1.recv(dest); // block for unique's data.
        chl1.recv(dest); // block for shared's data.

        // shared's refernce counter = 1.
    }
    
    
    // We can also perform asynchronous receive. In this case, we will tell the channel
    // where to store data in the future...
    {
        std::vector<int> dest;
        auto future = chl1.asyncRecv(dest); // will not block.

        // dest == {}

        // in the future, send the data.
        std::vector<int> data{ 0,1,2,3,4,5,6,7 };
        chl0.asyncSend(std::move(data)); // will not block.

        // dest == ???

        future.get(); // will block

        // dest == {0,1,...,7}
    }
    // The above asyncRecv(...) is not often used, but it has at least one  
    // advantage. The implementation of Channel is optimize to store the 
    // data directly into dest. As opposed to buffering it interally, and 
    // the later copying it to dest when Channel::recv(...) is called.


    // Channel::asyncSend(...) also support the pointer length interface.
    // In this case, it is up to the user to ensure that the lifetime 
    // of data is larger than the time required to send. In this case, we are
    // ok since chl1.recv(...) will block until this condition is true.
    {
        std::array<int, 4> data{ 0,1,2,3 };
        chl0.asyncSend(data.data(), data.size());


        std::vector<int> dest;
        chl1.recv(dest); 
    }


    // As an additional option for this interface, a call back 
    // function can be provided. This call back will be called
    // once the data has been sent.
    {
        int size = 4;
        int* data = new int[size]();

        chl0.asyncSend(data, size, [data]()
        {
            // we are done with data now, delete it.
            delete[] data;
        });


        std::vector<int> dest;
        chl1.recv(dest);
    }

    // Finally, there is also a method to make a deep copy and send asynchronously.
    {
        std::vector<int> data{ 0,1,2,3,4,5,6,7 };

        chl0.asyncSendCopy(data);


        std::vector<int> dest;
        chl1.recv(dest);
    }



    /*#####################################################
    ##                 Error Handling                    ##
    #####################################################*/

    // While not required, it is possible to recover from errors that 
    // are thrown when the receive buffer does not match the incoming 
    // data and can not be resized. Consider the following example
    {
        std::array<int, 4> data{ 0,1,2,3 };
        chl0.send(data);

        std::array<int, 2> dest;
        try 
        {
            // will throw, dest.size() != dat.size(); and no resize() member.
            chl1.recv(dest);
        }
        catch (BadReceiveBufferSize b)
        {
            // catch the error, creat a new dest in bytes.
            std::vector<u8> backup(b.mSize);

            // tell the 
            b.mRescheduler(backup.data());
        }
    }


    /*#####################################################
    ##                   Statistics                      ##
    #####################################################*/

    // Print interesting information.
    std::cout
        << "Connection: " << chl0.getEndpoint().getName() << std::endl
        << "   Channel: " << chl0.getName() << std::endl
        << "      Send: " << chl0.getTotalDataSent() << std::endl
        << "  received: " << chl0.getTotalDataRecv() << std::endl;

    // Reset the data sent coutners.
    chl0.resetStats();



    /*#####################################################
    ##                   Clean up                        ##
    #####################################################*/


    // close everything down in this order. Must be done.
    chl0.close();
    chl1.close();

    server.stop();
    client.stop();


    ios.stop();

}
