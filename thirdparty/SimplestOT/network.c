#include "network.h"

int server_listen(const int portno)
{
	int sockfd;
	struct sockaddr_in serv_addr;

	/* First call to socket() function */

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) 
	{
	    perror("ERROR opening socket"); exit(-1);
	}

	/* Initialize socket structure */

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);
 
	/* Now bind the host address using bind() call.*/

	if (bind(sockfd, (struct sockaddr *) &serv_addr,
	                      sizeof(serv_addr)) < 0)
	{
	     perror("ERROR on binding"); exit(-1);
	}

	/* Now start listening for the clients, here process will
	   go in sleep mode and will wait for the incoming connection */

	listen(sockfd, 1);

	return sockfd;
}

int server_accept(int sockfd)
{
	int newsockfd;
	socklen_t clilen;
	struct sockaddr_in cli_addr;

	clilen = sizeof(cli_addr);

	newsockfd = accept(sockfd, 
	                   (struct sockaddr *)&cli_addr, 
	                   &clilen);
	if (newsockfd < 0) 
	{
	    perror("ERROR on accept"); exit(-1);
	}

	return newsockfd;
}

void client_connect(int * sock, const char * host, const int portno)
{
    int sockfd;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    /* Create a socket point */

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) 
    {
        perror("ERROR opening socket"); exit(-1);
    }

	/* deal with host */

    server = gethostbyname(host);

    if (server == NULL) 
    {
        fprintf(stderr,"ERROR, no such host\n"); exit(0);
    }

	memset(&serv_addr, 0, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;

    memcpy( &(serv_addr.sin_addr.s_addr),
            server->h_addr, 
            server->h_length                      );

    serv_addr.sin_port = htons(portno);

    /* Now connect to the server */

    while( connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0 ) ;

    *sock = sockfd;	
}

void writing(int sockfd, void * buffer, const unsigned len)
{
	unsigned delivered = 0;
	int n;
	char * ptr = (char *) buffer;

	/* Send message to the server */

	while (delivered < len)
	{
		n = write(sockfd, ptr, len - delivered);

		if (n < 0) 
		{
			perror("ERROR writing to socket"); exit(-1);
		}

		else	
		{
			delivered += n;
			ptr += n;
		}
	}
}

void reading(int sockfd, void * buffer, const unsigned len)
{
	unsigned delivered = 0;
	int n;
	char * ptr = (char *) buffer;

	/* Send message to the server */

	while (delivered < len)
	{
		n = read(sockfd, ptr, len - delivered);

		if (n < 0) 
		{
			perror("ERROR reading from socket"); exit(-1);
		}

		else	
		{
			delivered += n;
			ptr += n;
		}
	}
}

