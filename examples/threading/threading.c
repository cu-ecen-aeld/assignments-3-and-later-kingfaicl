#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
//#define DEBUG_LOG(msg,...)
#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    //struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    struct thread_data *args = (struct thread_data *) thread_param;

    /* sleep for microseconds */
    DEBUG_LOG( "[%lu] Sleeping for %d ms before obtaining mutex", args->thread_no, args->wait_to_obtain );
    usleep( args->wait_to_obtain*1000 );

    /* obtain mutex */
    DEBUG_LOG( "[%lu] Obtaining mutex", args->thread_no );
    int rc = pthread_mutex_lock( args->mutex );
    if (rc != 0) {
	ERROR_LOG( "[%lu] pthread_mutex_lock() failed with %d", args->thread_no, rc );
    } else {

	/* sleep for microseconds */
	DEBUG_LOG( "[%lu] Sleeping for %d ms before releasing mutex", args->thread_no, args->wait_to_release );
	usleep( args->wait_to_release*1000 );

	/* release mutex */
	DEBUG_LOG( "[%lu] Releasing mutex", args->thread_no );
	rc = pthread_mutex_unlock( args->mutex );
	if (rc != 0) {
	    ERROR_LOG( "[%lu] pthread_mutex_unlock() failed with %d", args->thread_no, rc );
	} else {
	    args->thread_complete_success = true;
	}
    }
 
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */
    struct thread_data *threaddata = (struct thread_data *) malloc( sizeof( struct thread_data ) );
    /* set up threaddata & mutex */
    threaddata->thread_no = 0;
    threaddata->wait_to_obtain = wait_to_obtain_ms;
    threaddata->wait_to_release = wait_to_release_ms;
    threaddata->thread_complete_success = false;
    threaddata->mutex = mutex; /* already initialized by caller */
    DEBUG_LOG( "Creating thread" );
    int rc = pthread_create( thread, NULL, threadfunc, threaddata );
    if (rc == 0) {
	DEBUG_LOG( "Created thread [%lu]", *thread );
	threaddata->thread_no = *thread;
	return true;
    } else {
	ERROR_LOG( "pthread_create() failed with %d\n", rc );
    }
 
    return false;
}

