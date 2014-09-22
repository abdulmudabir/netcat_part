
/*
 * The TCP server construction needs the following steps:
 * 1. Create a TCP socket using socket()
 * 2. Bind this socket to a port number using bind()
 * 3. Allow the server to listen to incoming client connection request through this TCP welcoming socket using listen()
 * 4. Accept a client connection using accept() on a new socket and do this for as many client requests as needed
 * 5. Read or write data from & to the client via this new socket
 * 6. Close the client connection using close()
 * 
 * username: abdpatel@indiana.edu
 * 
 * References: 1. Chapter 2, TCP/IP Sockets in C
 * 	       2. http://www.linuxhowtos.org/C_C++/socket.htm   
 */

#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include "nc_args_t.h"

#include <openssl/hmac.h>		// need to add -lssl to compile
#include "shared_key.h"			// make server aware of the shared key

void promptError(char *);		/* written like this here instead of importing header in order to avoid 'multiple
					 * definition' error */

#define MAXQUEUE 5			// maximum number of pending client connections 

/**
 * This function creates a server to accept communication from client. The server keeps listening for incoming client connections 
 * on its 'welcoming-socket'. As soon as client knocks at server, server assigns a new socket to exchange data with client.
 * Basically, all data exchange from client is stored in a file in the server file system.
 *
 * Return:
 * 	void
 **/
void createServer(nc_args_t *nc_args) {
    
    int serverSockfd;				// server's client connection-welcoming socket
    int listenStatus;				// variable to indicate whether server is listening on its socket or no
    int newSocketfd;				// new socket on which server may exchange data with client
    char buffer[BUF_LEN];			// a buffer of size 2048 bytes at max to read or write data
    ssize_t bytesRead, totalBytesRead = 0;	// bytes read at a time; total number of bytes read by server
    FILE *fp;					// pointer to file where data will be written into
    //int i;					// loop iterator variable
    
    //unsigned char serverDigest[20];		// buffer that will have the computed message digest at server-side (20 bytes with sha1)
    //unsigned int serverDigestLen;		// integer that will receive number of bytes of server digest that were filled

    struct sockaddr_in clientAddr;		// to fill in all relevant client information
    
    // create the server's listening TCP stream socket
    if ( (serverSockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0 )
	promptError((char *) "Server was unable set up a listening socket");
    
    // bind the welcoming socket to a port number
    if ( bind(serverSockfd, (struct sockaddr *) &nc_args->servAddr, sizeof(nc_args->servAddr) ) < 0 )
	promptError((char *) "Server encountered error in binding its listening socket");
    
    // on successful server socket binding, server should listen to incoming client connections
    if ( ( listenStatus = listen(serverSockfd, MAXQUEUE) ) < 0 )		// listen to handle a maximum of 5 incoming client connections
	promptError((char *) "Server encountered error while trying to listen to incoming client connections");
    
    // we need to pass a pointer to address length of client, so store client address length first
    unsigned int clientAddrLength = sizeof(clientAddr);
    
    // server sets up a new socket to exchange data with client
    if ( ( newSocketfd = accept( serverSockfd, (struct sockaddr *) &clientAddr, &clientAddrLength ) ) < 0 )
	promptError((char *) "Server could not set up a new socket to communicate with client");
    
    /* now, read or write data from or to the new socket for as long as the server can */
        
    // the idea is to redirect everything that the server gets, into a file
    //fp = fopen("tempFile.txt", "w+");			// open a temporary file in read/write mode; file is created if does not exist
    fp = fopen(nc_args->serverFilename, "w+");
    //if (fp == NULL)
	//promptError( (char *) "ERROR: Could not open temporary file");
    
    memset(buffer, 0, BUF_LEN);		// flush out buffer by zero-ing it out, before reading or writing data
    
    while ( (bytesRead = read(newSocketfd, buffer, BUF_LEN)) != 0 ) {	/* read data from new socket and copy up to BUF_LEN bytes into file at a time;
									 * read until the amount to be read is 0 i.e. no more data to is available to read */
		
	totalBytesRead += bytesRead;		// track number of bytes being written to file
	
	fwrite(buffer, sizeof(char), bytesRead, fp);	// pour buffer contents into the temporary file
	
	memset(buffer, 0, BUF_LEN);	// flush out buffer after storing buffer contents
    }
        
    // read everything from temporary file and store it into a string -------------------------------------------------------------
    /*
    long fileSize = ftell(fp);		// current last position of fp in the file indicates the file size
    char *fileContentsStr = (char *) malloc(fileSize * sizeof(char) + 1);	// to read contents of file into a string
    fileContentsStr[fileSize] = '\0';	// set last character in string as NULL pointer to allow nothing more than the file contents to be written in string
    rewind(fp);				// set file pointer to the beginning of file
    fread(fileContentsStr, sizeof(char), fileSize, fp);
    printf("0. testing: fileContentsStr after file fp read: '%s'\n", fileContentsStr);
    rewind(fp);				// reset file pointer again to the beginning of file
    fclose(fp);				// close "tempFile.txt" after reading its contents into a string
    */
    // ------------------------------------------------------------------------------------------------------------------
    
    /*
    // split client's message and client's digest into separate strings at the server-side
    char *delim = ":";			// because ":" was used as delimiter between message and client's digest
    char *dataStr = strtok(fileContentsStr, delim);
    printf("testing: dataStr: '%s'\n", dataStr);
    char *clDigest = strtok(NULL, delim);
    printf("testing: clDigest: '%s'\n", clDigest);
    
    dataStr[strlen(dataStr)] = '\0';
    clDigest[strlen(clDigest)] = '\0';			// null termination of string
        
    // create a server digest using the message retrieved ---------------------------------------------------------------
    HMAC(EVP_sha1(), key, strlen(key), (unsigned char *) dataStr, strlen(dataStr), serverDigest, &serverDigestLen);
    
    // render MAC as 40 characters
    char mdString[41];			// store final server digest
    for (i = 0; i < 20; i++)
	sprintf(&mdString[i*2], "%02x", (unsigned int) serverDigest[i]);
    mdString[strlen(mdString)] = '\0';	// null termination of string
    printf("testing: server digest: '%s'\n", mdString);
    // ------------------------------------------------------------------------------------------------------------------
    
    // write client's message received by server to file specified by user
    fp = fopen(nc_args->serverFilename, "w+");
    if (fp == NULL)
	promptError( (char *) "ERROR: Could not write to file at server");
    fwrite(dataStr, sizeof(char), strlen(dataStr), fp);
    rewind(fp);			// set file pointer to beginning of file
    fclose(fp);			// close output file after writing to it
    
    // compare server's digest with client's digest to infer message integrity
    printf("testing: client message: '%s'\n", dataStr);
    printf("testing: client digest: '%s'\n", clDigest);
    if (strcmp(mdString, clDigest) == 0)
	printf("Server Digest matches with Client Digest!\n");
    else 
	printf("Server Digest does not match with Client Digest!\n");
    */  
    
    printf("Server says: %ld bytes written to file '%s'\n", totalBytesRead, nc_args->serverFilename);
    
    rewind(fp);			// set file pointer to beginning of file, else file will not close
    fclose(fp);			// close file
    
    // close the two sockets
    close(newSocketfd);
    close(serverSockfd);
        
    // free any other allocated memory during the client-server communication; NEED FIX !!
    /*
    free(nc_args->message);
    free(nc_args->filename);
    */
    
    // free allocated memory
    //free(fileContentsStr);		// free memory allocated to string read from file: tempFile.txt
    
    return;
    
}