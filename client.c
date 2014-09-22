
/*
 * Construct a TCP client to communicate with a server
 *
 * The TCP client needs to go through the following steps
 * 1. Create a TCP socket using socket()
 * 2. Establish a connection with server using connect()
 * 3. Send data to server using write()
 * 4. Close communication with server using close()
 *
 * username: abdpatel@indiana.edu
 * 
 * References: 1. Chapter 2, TCP/IP Sockets in C
 * 	       2. http://www.linuxhowtos.org/C_C++/socket.htm
 * 	       3. http://www.askyb.com/cpp/openssl-hmac-hasing-example-in-cpp/
 */

#include <stdio.h>			// for standard IO functions including file IO
#include <stdlib.h>			// for malloc(), atoi(), exit()
#include <sys/socket.h>			// for socket(), etc
#include <unistd.h>			// for close(), write()
#include <string.h>			// for strcpy(), strlen(), memset(), memmove()
#include <arpa/inet.h>			// for sockaddr_in, inet_ntoa(), etc.
#include <netdb.h>			// functions to access db that maps host names with host numbers
#include <sys/types.h>			// for data types

#include "nc_args_t.h"
#include "prompt_error.h"

#include <openssl/hmac.h>		// need to add -lssl to compile
#include "shared_key.h"			// make client aware of the shared key

/**
 * This function creates a client to communicate with a server. The client either 
 * sends a message or a file to the server through its TCP stream socket connected to server
 *
 * Return:
 * 	void
 **/
void createClient(nc_args_t *nc_args) {			// pass all relevant information earlier collected from user

    int clientSockfd;					// to create a client socket to handle communication with server
    char input[BUF_LEN];				// read/write buffer
    int smallRead;					// read only smallRead number of bytes specified by user
    int userBytesFlag = 0;				// to indicate that n_bytes is other than default value of 0
    ssize_t bytesRead = 0, bytesWritten = 0;		// track number of bytes read or written
    FILE *fp;						// pointer to client's input file
    
    //int i;						// loop iterator variable
    //unsigned char clientDigest[20];			// buffer that will have the computed message digest at client-side (20 bytes with sha1)
    //unsigned int clientDigestLen;			// integer that will receive number of bytes of client digest that were filled
    
    // zero out buffer: input
    memset(input, 0, BUF_LEN);
    
    // create the TCP stream socket
    if ( ( clientSockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) ) < 0 )	// non-negative socket() return value indicates failure in creating the socket
	promptError((char *) "TCP socket creation failed");
    
    // establish connection with server by calling connect on the client's TCP socket, sockfd
    if ( connect( clientSockfd, (struct sockaddr *) &nc_args->servAddr, sizeof(nc_args->servAddr) ) < 0 )
	promptError((char *) "Connection could not be established to server");
    
    /* now with a successful connection to server established, send data across through the socket using write */
        
    // if user typed in a message at command line instead of sending a file
    if (nc_args->message_mode) {			// message flag is on
	
	/* first, pour as much message data into input buffer as is needed */
	
	// case where only number of bytes to read is specified by user but not offset
	if ( nc_args->offset == 0 && nc_args->n_bytes > 0 && nc_args->n_bytes <= strlen(nc_args->message) ) {
	    // pour message into the input buffer but only up to n_bytes
	    strncpy(input, nc_args->message, nc_args->n_bytes);
	    input[nc_args->n_bytes] = '\0';	// null terminate the string in input buffer
	} else if (nc_args->n_bytes > strlen(nc_args->message)) {		// case where user specifies more bytes than there are in their message
	    promptError("ERROR: Cannot write bytes more than the input message. Please try again");
	} else {		// pour entire message into buffer if there's no requirement to read specified number of bytes 
	    strncpy(input, nc_args->message, strlen(nc_args->message));
	    input[strlen(nc_args->message)] = '\0';	// null terminate the string in input buffer	
	}
	
	/* once we have the right amount of message in the input buffer, we can create 
	 * the message's digest before sending it to server */
	//HMAC(EVP_sha1(), key, strlen(key), (unsigned char *) input, strlen(input), clientDigest, &clientDigestLen);
	//printf("testing: clientDigest just after HMAC: '%s'\n", clientDigest);
	
	/* SHA1 is known to produce 20-byte mac (or hash) which is rendered as 40 characters. So, 
	 * change the length of the hash value */
	/*
	char mdString[41];			// store final client digest
	for (i = 0; i < 20; i++)
	    sprintf(&mdString[i*2], "%02x", (unsigned int) clientDigest[i]);	// have 2 hex length values inserted to total digest to 40 characters
	mdString[strlen(mdString)] = '\0';	// null termination of string
	*/
	
	// add a marker add the end of the message in the input buffer to signal end of message in input buffer
	//strcat(input, ":");
		
	/* now club the message and the client digest into one input buffer; separated by our marker ":" */
	/*
	char *finalBuffer = (char *) malloc( strlen(input) + strlen(mdString) + 1);
	strcpy(finalBuffer, "");
	strcpy(finalBuffer, input);
	strcat(finalBuffer, mdString);
	finalBuffer[strlen(finalBuffer)] = '\0';	// null terminate the string in final buffer
	*/
	//printf("testing: finalBuffer: '%s'\n", finalBuffer);
	
	bytesWritten = write( clientSockfd, input, strlen(input) );		// write message with digest to client socket
	if (bytesWritten < 0)
	    promptError((char *) "ERROR: Client failed to write to socket");
	
    } else {	// user is sending a file across to the server
	
	fp = fopen(nc_args->clientFilename, "r");		// open client file in read mode only
	
	// check if file offset is required
	if (nc_args->offset != 0)
	    fseek(fp, nc_args->offset, 0);			// offset file pointer by offset value specified by user
	
	// check if only a specified number of bytes are required to be read
	if (nc_args->n_bytes != 0) {
	    smallRead = nc_args->n_bytes;
	    userBytesFlag = 1;					// set flag to signal a reduced file read
	} else
	    smallRead = BUF_LEN;
	
	if (fp != NULL) {
	    
	    if (userBytesFlag) {
		// read only user specified number of bytes
		if (smallRead <= BUF_LEN) {
		    
		    // CHECK (different file at server): converting each byte read into network byte and then storing it into input buffer
		    bytesRead = fread(input, sizeof(char), smallRead, fp);
		    bytesWritten = write( clientSockfd, input, strlen(input) );
		    goto END;
		} else {	// when data to be read is larger than buffer size
		    while (1) {
			bytesRead += fread(input, sizeof(char), BUF_LEN, fp);
			bytesWritten += write( clientSockfd, input, strlen(input) );
			if (bytesWritten >= smallRead)
			    break;
		    }
		}
	    } else {	// otherwise, read the entire file
		while ( fread(input, sizeof(char), smallRead, fp) ) {
		    bytesWritten += write( clientSockfd, input, strlen(input) );
		}
	    }
	   
	} else
	    promptError((char *) "ERROR: Could not open client input file");
	
	END:
	
	if (bytesWritten < 0)
	    promptError((char *) "ERROR: Could not send any data from client input file");
	else if (bytesWritten == 0)
	    promptError((char *) "The input client file seems empty because nothing was read from the file");
	
    }
    
    //printf("testing: reaches here\n");
    
    // if in file mode, close file that was read from
    if (nc_args->message_mode == 0) {
	// set file pointer to beginning of file in any case
	fseek(fp, SEEK_SET, 0);
    
	// close file being used to read
	fclose(fp);
    }
    
    // close client's socket to end terminate communication with server
    close(clientSockfd);
    
    return;
    
}