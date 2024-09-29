/*
 * aesdsocket.c
 *
 * AELD assignment 9
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
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <stdbool.h>
#include <pthread.h>
#include "queue.h"
#include "../aesd-char-driver/aesd_ioctl.h"

#define MYPORT "9000"  // the port users will be connecting to
#define BACKLOG 10     // how many pending connections queue will hold
#define USE_AESD_CHAR_DEVICE 1
#ifdef USE_AESD_CHAR_DEVICE
#define OUTPUTFILE "/dev/aesdchar"
#else
#define OUTPUTFILE "/var/tmp/aesdsocketdata"
#endif
#define CMD_KEYWORD "AESDCHAR_IOCSEEKTO"
#define BUFSIZE 4096
//#define BUFSIZE 100
#define PACKET_DELIMITER "\n"
//#define STR_LEN 80
#define STR_LEN 50

bool caught_sigint = false, caught_sigterm = false, caught_sigpipe = false;

struct thread_info 
{
    pthread_t thread_no;
    pthread_mutex_t *mutex; /* for exclusive write to out_fd */
    char *client_addr;
    int client_fd, out_fd;
    bool thread_complete_success;
};

#ifndef USE_AESD_CHAR_DEVICE
static void thread_timer( union sigval sigval ) 
{
    struct thread_info *tinfo = (struct thread_info *) sigval.sival_ptr;
    time_t now;
    char timestamp[STR_LEN+1];
    int len;

    now = time( NULL );
//  strftime( timestamp, STR_LEN+1, "timestamp:%Y.%m.%d.%H:%M:%S\n",
    /* RFC 2822-compliant date format */
    strftime( timestamp, STR_LEN+1, "timestamp:%a, %d %b %Y %T %z\n",
	      localtime( &now ) );
    len = strlen( timestamp );
    if (pthread_mutex_lock( tinfo->mutex ) != 0) {
	syslog( LOG_ERR, "Error %d (%s) locking mutex for timer thread",
		errno, strerror( errno ) );
    } else {
	/* write time to file */
	if (write( tinfo->out_fd, timestamp, len ) < len) {
	    syslog( LOG_ERR, "write(time) error: %s", strerror( errno ) );
	}
	if (pthread_mutex_unlock( tinfo->mutex ) != 0) {
	    syslog( LOG_ERR, "Error %d (%s) unlocking mutex for timer thread",
		    errno, strerror( errno ) );
	}
    }
}
#endif

void thread_joiner( void *ptr )
{
    struct thread_info *tinfo = (struct thread_info *) ptr;
    int rc = pthread_join( tinfo->thread_no, NULL );
    if (rc) {
	syslog( LOG_ERR, "pthread_join(%lu) failed with %d",
		tinfo->thread_no, rc );
    } else {
	syslog( LOG_DEBUG, "Joined thread %lu", tinfo->thread_no );
    }
}


void *conn_handler( void *thread_param ) 
{
    bool pending_data = true, handling_seek = false;
    struct thread_info *args = (struct thread_info *) thread_param;
    ssize_t bytes_read, packet_size, bytes_sent;
    char *read_buf, *line;
    struct aesd_seekto seekto;
    unsigned int write_cmd, offset;

    syslog( LOG_DEBUG, "Handling connection from %s", args->client_addr );

    /* allocate one additional byte to
       ensure read_buf is NULL-terminated */
    read_buf = (char *) malloc( BUFSIZE+1 );
    if (!read_buf) {
	syslog( LOG_ERR, "malloc(read_buf) error" );
	perror( "malloc()" );
	return thread_param;	/* return something non-NULL to indicate error */
    }

    /* read from the socket client,
       each time clearing & NULL-terminating the buffer for strtok() */
    for (memset( read_buf, 0, BUFSIZE+1 );
	 ((bytes_read = recv( args->client_fd, (void *) read_buf, BUFSIZE,
			      MSG_DONTWAIT )) > 0
//				     0 )) > 0
//				     MSG_WAITALL )) > 0
	  || pending_data)
	     && !caught_sigint && !caught_sigterm && !caught_sigpipe; ) {

	if (bytes_read <= 0) {
	    /* give the client another chance to send */
	    syslog( LOG_DEBUG,
		    "New connection, %ld data, give it another try",
		    bytes_read );
	    continue;
	} else {
	    pending_data = false;
	}
		
	syslog( LOG_DEBUG, "Received %ld bytes from %s [%s]", bytes_read,
		args->client_addr, read_buf );
		
	line = strtok( read_buf, PACKET_DELIMITER );
	if (!strncmp( line, CMD_KEYWORD, strlen( CMD_KEYWORD ) ) &&
	    sscanf( line, CMD_KEYWORD ":%u,%u", &write_cmd, &offset ) == 2) {
	    /* if line begins with the cmd keyword, handle seek command */
	    syslog( LOG_DEBUG,
		    "Handling ioctl seekto(%u,%u)", write_cmd, offset );
	    handling_seek = true;
	    seekto.write_cmd = write_cmd;
	    seekto.write_cmd_offset = offset;
	    if (ioctl( args->out_fd, AESDCHAR_IOCSEEKTO, &seekto ) < 0) {
		syslog( LOG_ERR, "ioctl error: %s", strerror( errno ) );
	    }
	} else {
	    /* handle regular data */
	    handling_seek = false;
	    packet_size = strlen( line ) + 1;
	    if (packet_size > BUFSIZE) {
		/* write out partial packet if buffer size exceeded */
		syslog( LOG_DEBUG,
			"Writing %ld bytes to file \"%s\"",
			(long) BUFSIZE, OUTPUTFILE );
		if (pthread_mutex_lock( args->mutex ) != 0) {
		    syslog( LOG_ERR, "Error %d (%s) locking mutex for thread %lu",
			    errno, strerror( errno ), args->thread_no );
		} else {
		    /* write to output file */
		    if (write( args->out_fd, read_buf, BUFSIZE ) < BUFSIZE) {
			syslog( LOG_ERR, "write(partial_pkt) error: %s",
				strerror( errno ) );
		    }
		    if (pthread_mutex_unlock( args->mutex ) != 0) {
			syslog( LOG_ERR,
				"Error %d (%s) unlocking mutex for thread %lu",
				errno, strerror( errno ), args->thread_no );
		    }
		}
	    } else {
		/* write each packet to the output file as a line */
		while (line) {
		    syslog( LOG_DEBUG,
			    "Writing %ld bytes to file \"%s\"",
			    packet_size, OUTPUTFILE );
		    if (pthread_mutex_lock( args->mutex ) != 0) {
			syslog( LOG_ERR,
				"Error %d (%s) locking mutex for thread %lu",
				errno, strerror( errno ), args->thread_no );
		    } else {
			/* write to output file */
			if (write( args->out_fd, line, packet_size-1 )
			    != packet_size-1
			    || write( args->out_fd, PACKET_DELIMITER, 1 ) != 1) {
			    syslog( LOG_ERR, "write(pkt) error: %s",
				    strerror( errno ) );
			    break; /* to cleanup in case of signal interrupts */
			}
			if (pthread_mutex_unlock( args->mutex ) != 0) {
			    syslog( LOG_ERR,
				    "Error %d (%s) unlocking mutex for thread %lu",
				    errno, strerror( errno ), args->thread_no );
			}
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
	}
    }
		
    /* done receiving on this client socket,
       start sending data back to client before closing socket */
    if (!handling_seek) {
	syslog( LOG_DEBUG, "Done receiving, rewinding file \"%s\"",
		OUTPUTFILE );
	if (lseek( args->out_fd, 0L, 0 ) < 0) {
	    syslog( LOG_ERR, "lseek() error: %s", strerror( errno ) );
	}
    }
    for (memset( read_buf, 0, BUFSIZE+1 );
	 (bytes_read = read( args->out_fd, read_buf, BUFSIZE )) > 0
	     && !caught_sigint && !caught_sigterm && !caught_sigpipe; ) {
	syslog( LOG_DEBUG, "Read %ld bytes from file \"%s\"",
		bytes_read, OUTPUTFILE );
	/* send partial packet if buffer size exceeded */
	bytes_sent = send( args->client_fd, (void *) read_buf,
			   bytes_read < BUFSIZE ?
			   bytes_read : BUFSIZE,
			   0 );
//				   MSG_DONTWAIT );
	if (bytes_sent == -1) {
	    syslog( LOG_ERR, "send() error: %s", strerror( errno ) );
	    break; /* to cleanup in case of signal interrupts */
	} else {
	    syslog( LOG_DEBUG, "Sent %ld bytes to %s",
		    bytes_sent, args->client_addr );
	    args->thread_complete_success = true;
	}
    }
    if (caught_sigpipe) {
	syslog( LOG_DEBUG, "Caught SIGPIPE" );
    }
    if (close( args->client_fd )) {
	syslog( LOG_ERR, "close(client_fd) error: %d (%s)\n",
		errno, strerror( errno ) );
    }
    syslog( LOG_DEBUG, "Closed connection from %s", args->client_addr );
    free( read_buf );
    return NULL;
} 


static void signal_handler( int signal_number )
{
    switch (signal_number) {
	case SIGINT:
	    caught_sigint = true;
	    break;
	    
	case SIGTERM:
	    caught_sigterm = true;
	    break;
	    
	case SIGPIPE:
	    caught_sigpipe = true;
	    
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
#ifndef USE_AESD_CHAR_DEVICE
    timer_t timer_id;
    struct sigevent sev;
    struct thread_info tinfo;
#endif
    struct thread_info *new_tinfo;
    pthread_mutex_t mutex;
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
    if (sigaction( SIGPIPE, &new_action, NULL ) != 0) {
	syslog( LOG_ERR, "Error %d (%s) registering for SIGPIPE",
		errno, strerror( errno ) );
	success = false;
    }
    if (success) {
	/* set up socket server */
	int status, fd = -1, sockfd, new_fd;
	struct sockaddr_storage their_addr;
	socklen_t addr_size;
	char addr_str[INET6_ADDRSTRLEN];
	int yes = 1;
	queue_node *thread_list = NULL;

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
	    return -1;
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
		syslog( LOG_ERR, "setsockopt() error: %d (%s)\n",
			errno, strerror( errno ) );
		if (close( sockfd )) {
		    syslog( LOG_ERR, "close() error: %d (%s)\n",
			    errno, strerror( errno ) );
		}
		return -1;
	    }

	    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
		syslog( LOG_ERR, "bind() error: %d (%s)\n",
			errno, strerror( errno ) );
		if (close( sockfd )) {
		    syslog( LOG_ERR, "close() error: %d (%s)\n",
			    errno, strerror( errno ) );
		}
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
		    if (close( sockfd )) {
			syslog( LOG_ERR, "close() error: %d (%s)\n",
				errno, strerror( errno ) );
		    }
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
	    if (close( sockfd )) {
		syslog( LOG_ERR, "close() error: %d (%s)\n",
			errno, strerror( errno ) );
	    }
	    return -1;
	}

	/* one mutex for all threads writing to the same output file */
	if (pthread_mutex_init( &mutex, NULL )) {
	    syslog( LOG_ERR, "Error initializing mutex: %d (%s)", errno,
		    strerror( errno ) );
	    return 1;
	}

#ifndef USE_AESD_CHAR_DEVICE

	/* delay opening of output file for aesdchar testing (Assignment 8) */
	syslog( LOG_DEBUG, "Opening file \"%s\" for write", OUTPUTFILE );
	fd = open( OUTPUTFILE, O_RDWR|O_TRUNC|O_CREAT, 0644 );
	if (fd < 0) {
	    syslog( LOG_ERR, "Error opening file \"%s\": %s", OUTPUTFILE,
		    strerror( errno ) );
	    if (close( sockfd )) {
		syslog( LOG_ERR, "close(sockfd) error: %d (%s)\n",
			errno, strerror( errno ) );
	    }
	    return 1;
	}
	syslog( LOG_DEBUG, "Opened file \"%s\" for write (%d)", OUTPUTFILE, fd );

	/* set up thread data for the timer thread */
	tinfo.out_fd = fd;
	tinfo.mutex = &mutex;
	tinfo.thread_no = 0;
	tinfo.thread_complete_success = false;

	/* set up timer thread */
	memset( &sev, 0, sizeof(struct sigevent) );
	sev.sigev_notify = SIGEV_THREAD;
	sev.sigev_value.sival_ptr = &tinfo;
	sev.sigev_notify_function = thread_timer;
	if (timer_create( CLOCK_MONOTONIC, &sev, &timer_id) != 0 ) {
            syslog( LOG_ERR, "Error creating timer: %d (%s)", errno,
		    strerror(errno) );
	    return 1;
        } else {
	    struct itimerspec itimerspec;
	    memset( &itimerspec, 0, sizeof(struct itimerspec) );
	    itimerspec.it_interval.tv_sec = 10;
	    itimerspec.it_value.tv_nsec = 1; /* arm the timer */
	    if (timer_settime( timer_id, 0, &itimerspec, NULL ) != 0) {
		syslog( LOG_ERR, "Error setting timer %d (%s)", errno,
			strerror(errno) );
		return 1;
	    }
	    syslog( LOG_DEBUG, "Created and armed timer" );
        }
#endif

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

	    /* set up thread info for the handler thread, add it to a list */
	    new_tinfo = (struct thread_info *) malloc(
		sizeof(struct thread_info) );
	    if (!new_tinfo) {
		syslog( LOG_ERR, "malloc(new_tinfo) error" );
		perror( "malloc()" );
		return 1;
	    }
	    queue_insert( (void *) new_tinfo, &thread_list );
	    if (fd == -1) {
		/* output file not yet opened; prepare output file */
		syslog( LOG_DEBUG, "Opening file \"%s\" for write", OUTPUTFILE );
		fd = open( OUTPUTFILE, O_RDWR|O_TRUNC|O_CREAT, 0644 );
		if (fd < 0) {
		    syslog( LOG_ERR, "Error opening file \"%s\": %s", OUTPUTFILE,
			    strerror( errno ) );
		    if (close( sockfd )) {
			syslog( LOG_ERR, "close(sockfd) error: %d (%s)\n",
				errno, strerror( errno ) );
		    }
		    return 1;
		}
	    }
	    new_tinfo->out_fd = fd;
	    new_tinfo->mutex = &mutex;
	    new_tinfo->thread_no = 0;
	    new_tinfo->thread_complete_success = false;
	    new_tinfo->client_addr = addr_str;
	    new_tinfo->client_fd = new_fd;

	    /* create thread to handle connection */
	    pthread_t t;
	    int rc = pthread_create( &t, NULL, conn_handler, new_tinfo );
	    if (rc) {
		syslog( LOG_ERR, "pthread_create() failed with %d\n", rc );
	    } else {
		syslog( LOG_DEBUG, "Created thread %lu", t );
		new_tinfo->thread_no = t;
	    }
	}
	if (caught_sigint) {
	    syslog( LOG_DEBUG, "Caught SIGINT, exiting" );
	}
	if (caught_sigterm) {
	    syslog( LOG_DEBUG, "Caught SIGTERM, exiting" );
	}

	/* cleanup */
	queue_foreach( thread_joiner, thread_list );
	queue_free( &thread_list );
#ifndef USE_AESD_CHAR_DEVICE
	if (timer_delete( timer_id ) != 0) {
	    syslog( LOG_ERR, "Error deleting timer %d (%s)", errno,
		    strerror(errno) );
	}
#endif
	if (close( fd )) {
	    syslog( LOG_ERR, "close(fd) error: %d (%s)\n",
		    errno, strerror( errno ) );
	}
#ifndef USE_AESD_CHAR_DEVICE
	syslog( LOG_DEBUG, "Deleting file \"%s\"", OUTPUTFILE );
	remove( OUTPUTFILE );
#endif
	if (close( sockfd )) {
	    syslog( LOG_ERR, "close(sockfd) error: %d (%s)\n",
		    errno, strerror( errno ) );
	}
	return 0;
    } else {
	return 1;
    }
}


