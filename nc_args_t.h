
#ifndef NC_ARGS_T_H_
#define NC_ARGS_T_H_

/**
 * Structure to hold all relevant state
 **/
typedef struct nc_args {
    struct sockaddr_in servAddr;		// server address information
    unsigned short port;			// server's listening port
    unsigned short listen;			// listen flag
    int n_bytes;				// number of bytes to send
    int offset;					// file offset
    int verbose;				// verbose output info
    int message_mode;				// to indicate message is being sent by client
    char *message;				// if message_mode is activated, this will store the message
    char *serverFilename;			// output file's name
    char *clientFilename;			// input file's name
} nc_args_t;

#define BUF_LEN 1024				// data buffer length

#endif