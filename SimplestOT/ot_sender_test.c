//#include <stdio.h>
//#include <string.h>
//#include <assert.h>
//
//#include "ot_sender.h"
//
//#include "ot_config.h"
//#include "network.h"
//#include "cpucycles.h"
//
//void ot_sender_test(SENDER * sender, int newsockfd)
//{
//	int i, j, k;
//	unsigned char S_pack[ SIMPLEST_OT_PACK_BYTES ];
//	unsigned char Rs_pack[4 * SIMPLEST_OT_PACK_BYTES];
//	unsigned char keys[ 2 ][ 4 ][ SIMPLEST_OT_HASHBYTES ];
//
//	//
//
//	sender_genS(sender, S_pack);
//	writing(newsockfd, S_pack, sizeof(S_pack));
//
//	//
//
//	for (i = 0; i < NOTS; i += 4)
//	{
//		reading(newsockfd, Rs_pack, sizeof(Rs_pack));
//
//		sender_keygen(sender, Rs_pack, keys);
//
//		//
//
//		if (SIMPLEST_OT_VERBOSE)
//		{
//			for (j = 0; j < 4; j++)
//			{
//				printf("%4d-th sender keys:", i+j);
//	
//				for (k = 0; k < SIMPLEST_OT_HASHBYTES; k++) printf("%.2X", keys[0][j][k]);
//				printf(" ");
//				for (k = 0; k < SIMPLEST_OT_HASHBYTES; k++) printf("%.2X", keys[1][j][k]);
//				printf("\n");
//			}
//
//			printf("\n");
//		}
//	}
//}
//
//int old_main_send(int argc, char * argv[])
//{
//	int sockfd; 
//	int newsockfd; 
//	int rcvbuf = BUFSIZE;
//	int reuseaddr = 1;
//
//	long long t = 0;
//
//	SENDER sender;
//
//	//
//
//	if (argc != 2) 
//	{
//		fprintf(stderr, "usage %s port\n", argv[0]); exit(-1);
//	}
//
//	//
//
//	sockfd = server_listen(atoi(argv[1]));
//	newsockfd = server_accept(sockfd);
//
//	if (setsockopt(newsockfd, SOL_SOCKET,    SO_RCVBUF,    &rcvbuf,    sizeof(rcvbuf)) != 0) { perror("ERROR setsockopt"); exit(-1); }
//	if (setsockopt(newsockfd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) != 0) { perror("ERROR setsockopt"); exit(-1); }
//
//t -= cpucycles_amd64cpuinfo();
//
//	ot_sender_test(&sender, newsockfd);
//
//t += cpucycles_amd64cpuinfo();
//
//	//
//
//	if (!SIMPLEST_OT_VERBOSE) printf("[n=%d] Elapsed time:  %lld cycles\n", NOTS, t);
//
//	shutdown (newsockfd, 2);
//	shutdown (sockfd, 2);
//
//	//
//
//	return 0;
//}
//
