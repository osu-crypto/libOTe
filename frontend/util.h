#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 



#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Network/Channel.h>
void senderGetLatency(osuCrypto::Channel& chl);

void recverGetLatency(osuCrypto::Channel& chl);
void getLatency(osuCrypto::CLP& cmd);

enum class Role
{
	Sender,
	Receiver
};
void sync(osuCrypto::Channel& chl, Role role);