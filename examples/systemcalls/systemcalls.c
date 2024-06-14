#include "systemcalls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{

/*
 * TODO  add your code here
 *  Call the system() function with the command set in the cmd
 *   and return a boolean true if the system() call completed with success
 *   or false() if it returned a failure
*/
	int retval = system( cmd );
	switch (retval) {
		case -1:
			syslog( LOG_ERR, "Child process could not be created: %s", strerror( errno ) );
			return false;
		default:
			syslog( LOG_DEBUG, "All system calls succeeded; last termination status: %d", retval );
	}
    return true;
}

/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
	syslog( LOG_DEBUG, "do_exec command %d/%d: %s", i+1, count, command[i] );
    }
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
 //   command[count] = command[count];

/*
 * TODO:
 *   Execute a system command by calling fork, execv(),
 *   and wait instead of system (see LSP page 161).
 *   Use the command[0] as the full path to the command to execute
 *   (first argument to execv), and use the remaining arguments
 *   as second argument to the execv() command.
 *
*/
	bool retval = true;
	pid_t pid = fork();
	switch (pid) {
	case 0:
		/* child process, do exec */
		syslog( LOG_DEBUG, "Child process, executing command \"%s\"", command[0] );
		if (execv( command[0], command ) == -1) {
			syslog( LOG_ERR, "Child process, execv error: %s", strerror( errno ) );
			retval = false;
		} 
		break;
	case -1:
		/* fork error */
		syslog( LOG_ERR, "Error forking child process: %s", strerror( errno ) );
		retval = false;
		break;
	default:	
		/* parent process, do wait */
		syslog( LOG_DEBUG, "Parent process (%s), waiting for child process %d to finish", command[0], pid );
		int wstatus, wretval;
		wretval = waitpid( pid, &wstatus, 0 );
		if (wretval == -1) {
			syslog( LOG_ERR, "Error executing child process: %s", strerror( errno ) );
			retval = false;
		} else if (!WIFEXITED( wstatus )) {
			syslog( LOG_ERR, "Abnormal child termination: %s", strerror( errno ) );
			retval = false;
		} else {
			syslog( LOG_DEBUG, "Parent process returning from child process %d with exit status: %d", pid, WEXITSTATUS( wstatus ) );
			if (wstatus != 0) retval = false;
		}
	}
    va_end(args);

    return retval;
}


/**
* @param outputfile - The full path to the file to write with command output.
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
	syslog( LOG_DEBUG, "do_exec_redirect command %d/%d: %s", i+1, count, command[i] );
    }
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
//    command[count] = command[count];


/*
 * TODO
 *   Call execv, but first using https://stackoverflow.com/a/13784315/1446624 as a refernce,
 *   redirect standard out to a file specified by outputfile.
 *   The rest of the behaviour is same as do_exec()
 *
*/
	bool retval = true;
	int fd = open( outputfile, O_WRONLY|O_TRUNC|O_CREAT, 0644 );
	if (fd < 0) {
		syslog( LOG_ERR, "Error opening file \"%s\": %s", outputfile, strerror( errno ) );
		retval = false;	
	} else {
	pid_t pid = fork();
	switch (pid) {
	case 0:
		/* child process, do exec */
		syslog( LOG_DEBUG, "Child process, executing command \"%s\"", command[0] );
		/* redirect standard input to file */
		if (dup2( fd, 1 ) < 0) {
			syslog( LOG_ERR, "Child process, dup2 error: %s", strerror( errno ) );
			retval = false;
		} else if (execv( command[0], command ) == -1) {
			syslog( LOG_ERR, "Child process, execv error: %s", strerror( errno ) );
			retval = false;
		} 
		break;
	case -1:
		/* fork error */
		syslog( LOG_ERR, "Error forking child process: %s", strerror( errno ) );
		retval = false;
		break;
	default:	
		/* parent process, do wait */
		syslog( LOG_DEBUG, "Parent process (%s), waiting for child process %d to finish", command[0], pid );
		int wstatus, wretval;
		wretval = wait( &wstatus );
		if (wretval == -1 || !WIFEXITED( wstatus )) {
			syslog( LOG_ERR, "Error executing child process or abnormal child termination: %s", strerror( errno ) );
			retval = false;
		} else {
			syslog( LOG_DEBUG, "Parent process returning from child process %d with exit status: %d", pid, WEXITSTATUS( wstatus ) );
			if (wstatus != 0) retval = false;
		}
	}
	close( fd );
	}
    va_end(args);

    return retval;
}
