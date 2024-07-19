/*
 * aesdsocket.c
 *
 * AELD assignment 5
 * Author: Clifford Loo
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>

#define MYPORT "9000"  // the port users will be connecting to
#define BACKLOG 10     // how many pending connections queue will hold
#define OUTPUTFILE "/var/tmp/aesdsocketdata"
#define BUFSIZE 4096
#define PACKET_DELIMITER "\n"

bool caught_sigint = false, caught_sigterm = false;

static void signal_handler( int signal_number )
{
    if (signal_number == SIGINT) {
	caught_sigint = true;
    } else if (signal_number == SIGTERM) {
	caught_sigterm = true;
    }
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main( int argc, char **argv )
{
    bool daemon = false;
    openlog( NULL, 0, LOG_USER );

    if (argc > 1) {
	if (argc != 2 || strcmp( argv[1], "-d" )) {
	    syslog( LOG_ERR, "Usage: %s [-d]\n", argv[0] );
	    printf( "Usage: %s [-d]\n", argv[0] );
	    return 1;
	} else {
	    daemon = true;
	}
    }

    /* register signal handler */
    struct sigaction new_action;
    bool success = true;
    memset( &new_action, 0, sizeof( struct sigaction ) );
    new_action.sa_handler = signal_handler;
    if (sigaction( SIGTERM, &new_action, NULL ) != 0) {
	syslog( LOG_ERR, "Error %d (%s) registering for SIGTERM",
		errno, strerror( errno ) );
	success = false;
    }
    if (sigaction( SIGINT, &new_action, NULL ) != 0) {
	syslog( LOG_ERR, "Error %d (%s) registering for SIGINT",
		errno, strerror( errno ) );
	success = false;
    }
    if (success) {
	/* set up socket server */
	int status, sockfd, new_fd;
	struct sockaddr_storage their_addr;
	socklen_t addr_size;
	char addr_str[INET6_ADDRSTRLEN];
	ssize_t bytes_read, packet_size, bytes_sent;
 	char *read_buf, *line;
	int yes = 1;

	/* load up address structs with getaddrinfo() */
	struct addrinfo hints;
	struct addrinfo *servinfo, *p;
	memset( &hints, 0, sizeof hints );
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if ((status = getaddrinfo( NULL, MYPORT, &hints, &servinfo )) != 0) {
	    syslog( LOG_ERR,
		    "getaddrinfo() error: %s\n", gai_strerror( status ) );
	    return 1;
	}

	/* loop through all the results and bind to the first available */
	for (p = servinfo; p != NULL; p = p->ai_next) {
	    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol))
		== -1) {
		syslog( LOG_ERR, "socket() error: %d (%s)\n",
			errno, strerror( errno ) );
		continue;
	    }

	    if (setsockopt( sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
			    sizeof(int) ) == -1) {
		close( sockfd );
		syslog( LOG_ERR, "setsockopt() error: %d (%s)\n",
			errno, strerror( errno ) );
		return 1;
	    }

	    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
		close( sockfd );
		syslog( LOG_ERR, "bind() error: %d (%s)\n",
			errno, strerror( errno ) );
		continue;
	    }

	    break;
	}
	freeaddrinfo( servinfo );

	if (daemon) {
	    pid_t pid = fork();
	    switch (pid) {
		case 0:
		    syslog( LOG_DEBUG, "Child process started" );
		    break;
		    
		case -1:
		    syslog( LOG_ERR, "Error forking child process: %s",
			    strerror( errno ) );
		    close( sockfd );
		    return 1;
		    
		default:
		    syslog( LOG_DEBUG,
			    "Parent process, started child %d, exiting",
			    pid );
		    return 0;
	    }
	}
	
	if (listen( sockfd, BACKLOG ) != 0) {
	    syslog( LOG_ERR, "listen() error: %d (%s)\n",
		    errno, strerror( errno ) );
	    close( sockfd );
	    return 1;
	}

	/* prepare output file */
	syslog( LOG_DEBUG, "Opening file \"%s\" for write", OUTPUTFILE );
//	FILE *file = fopen( OUTPUTFILE, "w+" );
//	if (file == NULL) {
//	    /* report error and exit */
//	    syslog( LOG_ERR, "Error opening file \"%s\": %s",
//		    OUTPUTFILE, strerror( errno ) );
//	    close( sockfd );
//	    return 1;	
//	}
	int fd = open( OUTPUTFILE, O_RDWR|O_TRUNC|O_CREAT, 0644 );
	if (fd < 0) {
	    syslog( LOG_ERR, "Error opening file \"%s\": %s", OUTPUTFILE,
		    strerror( errno ) );
	    return 1;
	}


	/* allocate one additional byte to ensure read_buf is NULL-terminated */
	read_buf = (char *) malloc( BUFSIZE+1 );
	if (!read_buf) {
	    syslog( LOG_ERR, "malloc() error" );
	    perror( "malloc()" );
	    close( sockfd );
//	    fclose( file );
	    close( fd );
	    return 1;
	}
	

	while (!caught_sigint && !caught_sigterm) {

	    /* accept an incoming connection */
	    addr_size = sizeof their_addr;
	    new_fd = accept( sockfd, (struct sockaddr *) &their_addr,
			     &addr_size );
	    if (new_fd == -1) {
		syslog( LOG_ERR, "accept() error: %d (%s)\n",
			errno, strerror( errno ) );
		break; /* to cleanup in case of signal interrupts */
	    }
	    inet_ntop( their_addr.ss_family,
		       get_in_addr( (struct sockaddr *) &their_addr ),
		       addr_str, sizeof addr_str );
	    syslog( LOG_DEBUG, "Accepted connection from %s", addr_str );

	    /* read from the socket client,
	       each time clearing & NULL-terminating the buffer for strtok() */
	    for (memset( read_buf, 0, BUFSIZE+1 );
		 (bytes_read = recv( new_fd, (void *) read_buf, BUFSIZE,
				     MSG_DONTWAIT )) > 0
//				     0 )) > 0
		     && !caught_sigint && !caught_sigterm; ) {
		syslog( LOG_DEBUG, "Received %ld bytes from %s", bytes_read,
			addr_str );
		
		line = strtok( read_buf, PACKET_DELIMITER );
		packet_size = strlen( line ) + 1;
		if (packet_size > BUFSIZE) {
		    /* write out partial packet */
		    syslog( LOG_DEBUG,
			    "Writing %ld bytes (starting at 0x%lx) "
			    "to file \"%s\"",
			    (long) BUFSIZE, (unsigned long) read_buf,
			    OUTPUTFILE );
//		    if (fwrite( read_buf, 1, BUFSIZE, file ) < BUFSIZE) {
//			syslog( LOG_ERR, "fwrite() error: %s",
//				strerror( errno ) );
		    if (write( fd, read_buf, BUFSIZE ) < BUFSIZE) {
			syslog( LOG_ERR, "write() error: %s",
				strerror( errno ) );
		    }
		} else {
		    /* write each packet to the output file as a line */
		    while (line) {
			syslog( LOG_DEBUG,
				"Writing %ld bytes (starting at 0x%lx) "
				"to file \"%s\"",
				packet_size, (unsigned long) line,
				OUTPUTFILE );
//			if (fprintf( file, "%s\n", line ) < 0) {
//			    syslog( LOG_ERR, "fprintf() error: %s",
//				    strerror( errno ) );
			if (write( fd, line, packet_size-1 ) != packet_size-1 ||
			    write( fd, PACKET_DELIMITER, 1 ) != 1) {
			    syslog( LOG_ERR, "write() error: %s",
				    strerror( errno ) );
			    break; /* to cleanup in case of signal interrupts */
			}
			if (packet_size < bytes_read) {
			    line = strtok( NULL, PACKET_DELIMITER );
			    packet_size = strlen( line ) + 1;
			} else {
			    /* no more packets; ignore remaining bytes
			       in the buffer */
			    line = NULL;
			}
		    }
		}
//		if (!fflush( file )) {
//		    syslog( LOG_ERR, "fflush() error: errno %d (%s), ferror %d",
//			    errno, strerror( errno ), ferror( file ) );
//		}
	    }

	    if (bytes_read < 0) {
		syslog( LOG_ERR, "recv() error: %s (bytes read = %ld)",
			strerror( errno ), bytes_read );
		/* to cleanup in case of signal interrupts */
	    }
	    /* done receiving, start sending data back to client */
	    syslog( LOG_DEBUG, "Done receiving from %s", addr_str );
	    syslog( LOG_DEBUG, "Rewinding file \"%s\"", OUTPUTFILE );
//	    rewind( file );
	    if (lseek( fd, 0L, 0 ) < 0) {
		syslog( LOG_ERR, "lseek() error: %s", strerror( errno ) );
	    }
	    for (memset( read_buf, 0, BUFSIZE+1 );
//		 (bytes_read = fread( read_buf, 1, BUFSIZE, file )) > 0
		 (bytes_read = read( fd, read_buf, BUFSIZE )) > 0
		     && !caught_sigint && !caught_sigterm; ) {
		syslog( LOG_DEBUG, "Read %ld bytes from file \"%s\"",
			bytes_read, OUTPUTFILE );
		bytes_sent = send( new_fd, (void *) read_buf,
				   bytes_read < BUFSIZE ? bytes_read : BUFSIZE,
				   0 );
		if (bytes_sent == -1) {
		    syslog( LOG_ERR, "send() error: %s", strerror( errno ) );
		    break; /* to cleanup in case of signal interrupts */
		} else {
		    syslog( LOG_DEBUG, "Sent %ld bytes to %s",
			    bytes_sent, addr_str );
		}
	    }
	    syslog( LOG_DEBUG, "Closed connection from %s", addr_str );
	    close( new_fd );
	}
	if (caught_sigint) {
	    syslog( LOG_DEBUG, "Caught SIGINT, exiting" );
	}
	if (caught_sigterm) {
	    syslog( LOG_DEBUG, "Caught SIGTERM, exiting" );
	}

	/* cleanup */
	free( read_buf );
//	fclose( file );
	close( fd );
	syslog( LOG_DEBUG, "Deleting file \"%s\"", OUTPUTFILE );
	remove( OUTPUTFILE );
	close( sockfd );
	return 0;
    } else {
	return 1;
    }
}


