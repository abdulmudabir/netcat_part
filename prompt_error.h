
/*
 * header file for function: promptError
 */

#ifndef PROMPT_ERROR_H_
#define PROMPT_ERROR_H_

// displays an error to the standard output

#include <stdio.h>
#include <stdlib.h>				// for exit()

void promptError(char *errorMessage) {
	perror(errorMessage);
	exit(1);				// indicate that program terminated unsuccessfully
}

#endif
