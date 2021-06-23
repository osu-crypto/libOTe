//#include <stdlib.h>
//#include <stdio.h>
//#include <string.h>
//#include <assert.h>
//
//#include "ot_receiver.h"
//
//#include "ot_config.h"
//#include "randombytes.h"
//#include "network.h"
//#include "cpucycles.h"
//
//void SimplestOT_recv(RECEIVER * receiver, int sockfd)
//{
//	int i, j, k;
//
//	unsigned char Rs_pack[ 4 * SIMPLEST_OT_PACK_BYTES ];
//	unsigned char keys[ 4 ][ SIMPLEST_OT_HASHBYTES ];
//	unsigned char cs[ 4 ];
//
//	//
//
//	reading(sockfd, receiver->S_pack, sizeof(receiver->S_pack));
//	receiver_procS(receiver);
//
//	//
//
//	receiver_maketable(receiver);
//
//	for (i = 0; i < NOTS; i += 4)
//	{
//		randombytes(cs, sizeof(cs));
//
//		for (j = 0; j < 4; j++)
//		{ 
//			cs[j] &= 1;
//
//			if (SIMPLEST_OT_VERBOSE) printf("%4d-th choose bit = %d\n", i+j, cs[j]);
//		}
//
//		receiver_rsgen(receiver, Rs_pack, cs);
//
//		writing(sockfd, Rs_pack, sizeof(Rs_pack));
//
//		receiver_keygen(receiver, keys);
//	
//		//
//
//		if (SIMPLEST_OT_VERBOSE)
//		{
//			for (j = 0; j < 4; j++)
//			{
//				printf("%4d-th reciever key:", i+j);
//
//				for (k = 0; k < SIMPLEST_OT_HASHBYTES; k++) printf("%.2X", keys[j][k]);
//				printf("\n");
//			}
//		}
//	}
//}
//
//
//int old_main_recv(int argc, char * argv[])
//{
//	int sockfd;
//	int sndbuf = BUFSIZE;
//	int flag = 1;
//
//	long long t = 0;
//
//	RECEIVER receiver;
//
//	//
//
//	if (argc != 3) 
//	{
//		fprintf(stderr,"usage %s hostname port\n", argv[0]); exit(-1);
//	}
//
//	//
//
//	client_connect(&sockfd, argv[1], atoi(argv[2]));
//
//	if( setsockopt(sockfd,  SOL_SOCKET,   SO_SNDBUF, &sndbuf, sizeof(int)) != 0 ) { perror("ERROR setsockopt"); exit(-1); }
//	if( setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY,   &flag, sizeof(int)) != 0 ) { perror("ERROR setsockopt"); exit(-1); }
//
//t -= cpucycles_amd64cpuinfo();
//
//	SimplestOT_recv(&receiver, sockfd);
//
//t += cpucycles_amd64cpuinfo();
//
//	//
//
//	if (!SIMPLEST_OT_VERBOSE) printf("[n=%d] Elapsed time:  %lld cycles\n", NOTS, t);
//
//	shutdown (sockfd, 2);
//
//	//
//
//	return 0;
//}
//
