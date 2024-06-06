/*
 * "writer.c"
 * AELD assignment 2: C programme to replace "writer.sh" of assignment 1
 */
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

int main( int argc, char **argv )
{
	int i;
	char *fullpath, *writestr;
	FILE *file = fopen( fullpath, "w" );
	openlog( NULL, 0, LOG_USER );
	if (argc < 2) {
		/* expected arguments not found */
		syslog( LOG_ERR, "Insufficient arguments: expected <full_path> <write_string>" );
		return 1;
	} else {
		fullpath = argv[1];
		writestr = argv[2];
		/* create/overwrite the file */
		syslog( LOG_DEBUG, "Opening file \"%s\" for write", fullpath );
		FILE *file = fopen( fullpath, "w" );
		if (file == NULL) {
			/* report error and exit */
			syslog( LOG_ERR, "Error opening file %s: %s", fullpath, strerror( errno ) );
			return 1;	
		} else {	
			/* write the string to the file */
			syslog( LOG_DEBUG, "Writing \"%s\" to file \"%s\"", writestr, fullpath );
			if (fprintf( file, "%s\n", writestr ) < 0) {
				syslog( LOG_ERR, "Write error: %s", strerror( errno ) );
				return 1;
			}
			fclose( file );
		}			
	}
	return 0;
} 
