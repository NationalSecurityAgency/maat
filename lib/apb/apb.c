/*
 * Copyright 2022 United States Government
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/**
 * apb.c: core functions for implementing an APB. Primarily invoking
 * ASPs. Also, generating and transmitting a measurement contract.
 */
#include <config.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <common/asp_info.h>
#include <common/apb_info.h>
#include <util/inet-socket.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <util/util.h>
#include <util/maat-io.h>
#include <limits.h>
#include <fcntl.h>

#include <apb/contracts.h>
#include <apb.h>

#ifdef ENABLE_SELINUX
#include <selinux/context.h>
#include <selinux/selinux.h>
#endif

#define INITIAL_BUFFER_SIZE (1 << 20)
#define BUFFER_INCREMENT INITIAL_BUFFER_SIZE
#define MAX_BUFFER_SIZE (1 << 30)

/*
 * Ugly global variable propagate ASP execution context settings into
 * APBs. These variables are defined in apbmain.c
 *
 * XXX: We currently don't propagate APB execution context settings,
 * so if an APB launches sub-APBs, the wrong thing may happen
 */
extern execcon_unique_categories_t libmaat_apbmain_asps_use_unique_categories;
extern respect_desired_execcon_t libmaat_apbmain_asps_respect_desired_execcon;


/*
 * Ugly global variable propagate ASP execution context settings into
 * APBs. These variables are defined in apbmain.c
 *
 * XXX: We currently don't propagate APB execution context settings,
 * so if an APB launches sub-APBs, the wrong thing may happen
 */
//extern execcon_unique_categories_t libmaat_apbmain_asps_use_unique_categories;
//extern respect_desired_execcon_t libmaat_apbmain_asps_respect_desired_execcon;

static int asp_is_running(struct asp *asp)
{
    return asp->pid > 0;
}

/**
 * Calls waitpid() on the pid of the passed asp
 * Returns -EINVAL if asp is NULL or not running,
 *         -1 if waitpid() failed,
 *         WIFEXTED of the exit status of the ASP otherwise
 */
int wait_asp(struct asp *asp)
{
    int exitstatus = 0;
    int ret_val = 0;
    if (!asp || !asp_is_running(asp)) {
        return -EINVAL;
    }

    ret_val = waitpid(asp->pid, &exitstatus, 0);
    if (ret_val == -1) {
        dlog(0, "Error: waitpid failure\n");
        return ret_val;
    }

    asp->pid = 0;

    if (WIFEXITED(exitstatus)) {
        dlog(4, "PID %d exited with status %d\n", asp->pid, WEXITSTATUS(exitstatus));
        return WEXITSTATUS(exitstatus);
    } else {
        dlog(4, "PID %d exited without an exit status\n", asp->pid);
        return 0;
    }
}

/**
 * kills the pid of the passed asp
 */
int stop_asp(struct asp *asp)
{
    int ret_val = 0;
    if (!asp) {
        return -ENOENT;
    }

    //function description says this is supposed to call the ASP's exit function
    dlog(2, "Sending SIGHUP to pid %d\n", asp->pid);
    kill(asp->pid, SIGHUP);

    sleep(3);

    dlog(2, "Sending SIGKILL to pid %d\n", asp->pid);
    kill(asp->pid, SIGKILL);

    asp->pid     = 0;
    return ret_val;
}

/*
 * Spawns a child process which will run the asp specified by the asp struct. The specified infd and
 * outfd will be passed to the command line as a file descriptor to read from and a file descriptor to
 * write to, respectively, to the child as long as they are non-negative, otherwise, they are ignored.
 * If the async flag is true, then the asp will execute asynchronously, and must be waited upon using
 * wait_asp and can be killed using stop_asp. The asp_argv should contain arguments for the ASP and should
 * contain a number of arguments equal to asp_argc. The arguments will be provided to the ASP as:
 *
 * <executable_name> [infd] [outfd] [libcap capabilities, if support is enabled] [arguments in argv]
 *
 * The variadic arguments are used to specify file descriptors that are meant to be closed in the child.
 * Provide all of the file descriptors followed by a -1 to indicate termination of the list. NOTE THAT
 * A -1 IS REQUIRED EVEN IF NO FILE DESCRIPTORS ARE SPECIFIED - the variadic arguments parsing library
 * will not know where to stop parsing otherwise and may close all sorts of random file descriptors.
 */
int run_asp(struct asp *asp, int infd, int outfd, bool async, int asp_argc, char *asp_argv[], ...)
{
    pid_t pid = 0;

    pid = fork();
    if(pid < 0) {
        dlog(0, "Fork failed: %s\n", strerror(errno));
        return -1;
    } else if(pid > 0) {
        //Executing in the parent
        asp->pid = pid;

        if(async) {
            return 0;
        } else {
            return wait_asp(asp);
        }
    }

    //Executing in the child

    /* Make sure any sensitive file descriptors are closed in the child */
    int fd, len, err;
    va_list args;
    va_start(args, asp_argv);
    while((fd = va_arg(args, int)) != -1) {
        close(fd);
    }
    va_end(args);

    int aspmain_argc = 0;
    char *aspmain_argv[asp_argc + 10];

    aspmain_argv[aspmain_argc] = asp->file->full_filename; /* max(aspmain_argc) = 0 */

    /* Only hand descriptors to child if they represent possible descriptors usable by the child
     * Note: this does not only fulfill a protective purpose: some ASPs do not take an Infd and Outfd,
     * or at least not in this order. Defining these as negative 1 allows you to do this manually in argv */
    if (infd > -1) {
        len = snprintf(NULL, 0, "%d", infd);
        if(len < 0) {
            dlog(0, "Unable to represent the in file descriptor as a string\n");
            return -1;
        }

        /* Type coercion is justified because the value of len+1 should not exceed
         * the semantic length of a file descriptor, which is lower than the maximum
         * value which can be expressed by a size_t */
        aspmain_argv[++aspmain_argc] = malloc((size_t)(len + 1)); /* max(aspmain_argc) = 1 */
        if(aspmain_argv[aspmain_argc] == NULL) {
            dlog(0, "Unable to allocate memory for temporary buffer\n");
            return -1;
        }

        /* Type coercion is justified because the length of the buffer will never exceed the
         * maximum semantic length of an int, which should be smaller than a size_t */
        err = snprintf(aspmain_argv[aspmain_argc], (size_t)(len + 1), "%d", infd);
        if(err < len) {
            dlog(0, "Unable to convert the in file descriptor to a string\n");
            free(aspmain_argv[aspmain_argc]); /* infd slot */
            return -1;
        }
    }

    if(outfd > -1) {
        len = snprintf(NULL, 0, "%d", outfd);
        if(len < 0) {
            dlog(0, "Unable to represent the out file descriptor as a string\n");
            free(aspmain_argv[aspmain_argc]); /* infd slot */
            return -1;
        }

        /* Type coercion is justified because the value of len+1 should not exceed
         * the semantic length of a file descriptor, which is lower than the maximum
         * value which can be expressed by a size_t */
        aspmain_argv[++aspmain_argc] = malloc((size_t)(len + 1));  /* max(aspmain_argc) = 2 */
        if(aspmain_argv[aspmain_argc] == NULL) {
            dlog(0, "Unable to allocate memory for temporary buffer\n");
            free(aspmain_argv[aspmain_argc-1]); /* infd slot */
            return -1;
        }

        /* Type coercion is justified because the length of the buffer will never exceed the
         * maximum semantic length of an int, which should be smaller than a size_t */
        err = snprintf(aspmain_argv[aspmain_argc], (size_t)(len + 1), "%d", outfd);
        if(err < len) {
            dlog(0, "Unable to convert the out file descriptor to a string\n");
            free(aspmain_argv[aspmain_argc]);    /* outfd */
            free(aspmain_argv[aspmain_argc-1]);  /* infd */
            return -1;
        }
    }

#ifdef USE_LIBCAP
    char *cap_str = NULL;

    if(asp->desired_sec_ctxt.cap_set) {
        cap_str = cap_to_text(asp->desired_sec_ctxt.capabilities, NULL);
        aspmain_argv[++aspmain_argc] = "-c";              /* max(aspmain_argc) = 3 */
        aspmain_argv[++aspmain_argc] = cap_str;           /* max(aspmain_argc) = 4 */
    }
#endif

    //Copy args over
    for(int i = 0; i < asp_argc; i++) {
        aspmain_argv[++aspmain_argc] = asp_argv[i];
    }

    aspmain_argc++;
    aspmain_argv[aspmain_argc] = NULL;

    exe_sec_ctxt_set_execcon(asp->file->full_filename,
                             &asp->desired_sec_ctxt,
                             libmaat_apbmain_asps_respect_desired_execcon,
                             libmaat_apbmain_asps_use_unique_categories,
                             256, 0, 0);

    dlog(5, "PRESENTATION MODE (self): APB forks ASP of name %s.\n", asp->name);
    dlog(6, "Executing ASP executable: %s\n", asp->file->full_filename);
    execv(asp->file->full_filename, aspmain_argv);
    dlog(0, "Failed to exec the ASP \"%s\": %s\n", asp->name, strerror(errno));

    return -1;
}

/*
 * This function invokes run_asp but uses a user supplied buffer input source and output destination
 * instead of file descriptors. This is more ergonomic in certain use-cases that utilizing file descriptors.
 * This function returns the following:
 * -5: Error in creating pipes to communicate with the ASP's process
 * -4: Error in running the ASP
 * -3: Error in writing the input buffer to the ASP
 * -2: Error in reading the output buffer from the ASP
 * -1: Error in wating on the ASP
 * 0: Successful execution
 */
int run_asp_buffers(struct asp *asp, const unsigned char *buf_in,
                    size_t buf_in_len, char **out_buf,
                    size_t *buf_out_len, int asp_argc,
                    char *asp_argv[], int timeout,
                    ...)
{
    int ret           = -5;
    int rc            = -1;
    int eof_enc       = -1;
    size_t written    = -1;
    size_t tmp_len    = 0;
    size_t bytes_read = 0;
    char *tmp         = NULL;
    int data_in[2]    = {0};
    int data_out[2]   = {0};

    if (buf_in != NULL) {
      rc = pipe(data_in);
      if (rc < 0) {
        dlog(0, "Failure to create pipe for providing data to ASP\n");
        goto in_pipe_err;
      }

      rc = maat_io_channel_new(data_in[0]);
      if (rc < 0) {
        dlog(0, "Failure to initialize pipe read end\n");
        goto in_read_err;
      }

      rc = maat_io_channel_new(data_in[1]);
      if (rc < 0) {
        dlog(0, "Failure to initialize pipe write end\n");
        goto in_write_err;
      }
    }

    rc = pipe(data_out);
    if (rc < 0) {
        dlog(0, "Failure to create pipe for providing data to ASP\n");
        goto out_pipe_err;
    }

    rc = maat_io_channel_new(data_out[0]);
    if (rc < 0) {
        dlog(0, "Failure to initialize pipe read end\n");
        goto out_read_err;
    }

    rc = maat_io_channel_new(data_out[1]);
    if (rc < 0) {
        dlog(0, "Failure to initialize pipe write end\n");
        goto out_write_err;
    }

    ret = -4;
    if (buf_in != NULL) {
      rc = run_asp(asp, data_in[0], data_out[1], true, asp_argc,
		   asp_argv, data_in[1], data_out[0], -1);
      close(data_in[0]);
    } else {
      rc = run_asp(asp, STDIN_FILENO, data_out[1], true, asp_argc,
		   asp_argv, data_in[1], data_out[0], -1)
    }

    if(rc < 0) {
        dlog(0, "Failed to execute fork and buffer for %s ASP\n",
             asp->name);
        goto run_asp_err;
    }

    close(data_out[1]);

    ret = -3;
    if (buf_in != NULL) {
      rc = maat_write_sz_buf(data_in[1], buf_in, buf_in_len,
                           &written, timeout);
      if(rc < 0) {
        dlog(0, "Error writing input to channel\n");
        stop_asp(asp);
        goto write_failed;
      }

      close(data_in[1]);
    }

    ret = -2;
    rc = maat_read_sz_buf(data_out[0], &tmp, &tmp_len,
                          &bytes_read, &eof_enc,
                          timeout, INT_MAX);
    if(rc < 0 && rc != -EAGAIN) {
        dlog(0, "Error reading output from channel\n");
        goto read_failed;
    } else if (eof_enc != 0) {
        dlog(0, "Error: EOF encountered before complete buffer read\n");
        goto eof_enc;
    }

    close(data_out[0]);

    ret = -1;
    rc = wait_asp(asp);
    if (rc < 0) {
        goto wait_err;
    } else {
        ret = 0;
    }

    *out_buf = tmp;
    *buf_out_len = tmp_len;

wait_err:
    return ret;

write_failed:
    if (buf_in != NULL) {
      close(data_in[1]);
    }
read_failed:
eof_enc:
    if (buf_in != NULL) {
      close(data_in[0]);
    }
    return ret;

run_asp_err:
out_write_err:
out_read_err:
    close(data_out[0]);
    close(data_out[1]);
out_pipe_err:
in_write_err:
in_read_err:
    if (buf_in != NULL) {
      close(data_in[0]);
      close(data_in[1]);
    }
in_pipe_err:
    return ret;
}

/*
 * Read all of the data on a file descriptor until an EOF is reached or an error occurs
 * The buffer is not pre-allocated by the caller - instead, the buffer starts at
 * INITIAL_BUFFER_SIZE and is expanded in size by BUFFER_INCREMENT as needed, until
 * a hard limit of MAX_BUFFER_SIZE is reached. Returns 0 if an EOF is reached and
 * a negative number otherwise.
 */
static int maat_read_all(int infd, char **bufout, size_t *szout)
{
    char *buf;
    size_t tmpsize = INITIAL_BUFFER_SIZE;
    buf = malloc(tmpsize);
    if(buf == NULL) {
        return -1;
    }
    size_t offset = 0;
    while(tmpsize < MAX_BUFFER_SIZE) {
        ssize_t nread = read(infd, buf + offset, tmpsize -  offset);
        if(nread == 0) { /* EOF reached */
            *bufout = buf;
            *szout  = offset;
            return 0;
        }
        if(nread < 0) {
            free(buf);
            *bufout = NULL;
            *szout  = 0;
            return -1;
        }
        offset += (size_t)nread;

        if(offset == tmpsize) {
            tmpsize += BUFFER_INCREMENT;
            char *tmp = realloc(buf, tmpsize);
            if(tmp == NULL) {
                goto fail;
            }
            buf = tmp;
        }
    }
    errno = ENOBUFS;

fail:
    free(buf);
    *bufout = NULL;
    *szout = 0;
    return -1;
}

/*
 * Writes sz amount of data in the buffer to outfd. Return a negative number on error
 * and a zero on success
 */
static int maat_write_all(int outfd, char *buf, size_t sz)
{
    size_t total_written = 0;
    while(total_written < sz) {
        ssize_t tmp_written = write(outfd, buf + total_written, sz - total_written);
        if(tmp_written < 0) {
            if(errno != EAGAIN && errno != EWOULDBLOCK) {
                return -1;
            }
        }
        total_written += (size_t)tmp_written;
    }
    return 0;
}

/**
 * The purpose of this function is to fork a child process and for the child to read from infd
 * unil it is no longer able to do so, at which point the child forks off a grandchild which returns
 * while the child writes the data recieved from the parent to a pipe shared by the child and grandchild
 * and then waits until the grandchild dies at which point it exits. If infd is blocking, then this can
 * function as a form of control/data flow - the grandchild will not start execution until the parent is
 * completely finished writing to infd.
 *
 * This method could support sequential forms of ASP execution where one ASP needs to complete and send
 * it's data to the next ASP before it can start execution.
 *
 * In the parent, pidout is the pid of the child process. This is unused in the grandchild. In the grandchild,
 * pipe_read_out is set to the read end of the pipe shared by the child and the grandchild. From this the
 * grancchild can read the output of the parent. In the parent this is set to -1. infd is the file descriptor
 * used to send output from the parent to the grancchild. The remaining arguments are file descriptors that
 * should be closed in the grandchild.
 *
 * The function returns the pid of the child process on success in the parent, 0 in the grandchild, and -1
 * otherwise
 */
int fork_and_buffer(pid_t *pidout, int *pipe_read_out, int infd, ...)
{
    int rc = fork();
    if(rc < 0) {
        dlog(0, "Fork of buffer process failed: %s\n", strerror(errno));
        return -1;
    }

    /*
     * Code block executed only by the parent, records PID of child
     * to give back to the caller
     */
    if(rc > 0) {
        close(infd);
        *pidout = (pid_t) rc;
        *pipe_read_out = -1;
        return rc;
    }

    va_list ap;
    va_start(ap, infd);
    int closeme;
    while((closeme = va_arg(ap, int)) != -1) {
        close(closeme);
    }
    va_end(ap);

    /* From here on out we use exit(-1) to immediately terminate on
     * error rather than `return -1. We don't want the child to
     * attempt ot handle the error and continue execution.
     */

    char *buf;
    size_t sz;
    rc = maat_read_all(infd, &buf, &sz);
    if(rc < 0) {
        dlog(0, "Buffering process failed to read all of input: %s\n", strerror(errno));
        exit(-1);
    }

    int pfds[2];

    rc = pipe(pfds);
    if(rc != 0) {
        dlog(0, "Failed to create pipe for buffer output: %s\n", strerror(errno));
        free(buf);
        exit(-1);
    }

    pid_t pid = fork();

    if (pid < 0) {
        dlog(0, "Fork of buffer output process failed: %s\n", strerror(errno));
        close(pfds[0]);
        close(pfds[1]);
        free(buf);
        exit(-1);
    }

    if(pid == 0) {
        /* we're in the grandchild. we need to return the read end
         * of the pipe so future generations can receive the buffered
         * input from the child.
         *
         * We must also clean up by freeing the buffered input and
         * closing the write end of the pipe.
         */
        *pipe_read_out = pfds[0];
        free(buf);
        close(pfds[1]);
        return 0;
    }

    /* in the child. NB: the calling program isn't expecting this
     * branch to ever return, we must explicitly exit rather than
     * returning. */
    close(pfds[0]);
    rc = maat_write_all(pfds[1], buf, sz);
    if(rc < 0) {
        dlog(0, "Failed to write entire buffer: %s\n", strerror(errno));
        close(pfds[1]);
        free(buf);
        exit(-1);
    }

    /* wait for the grandchild before exiting. */
    waitpid(pid, NULL, 0);

    exit(0);
    /* unreachable return statement to make the compiler happy */
    return 0;
}

/**
 * This function asynchronously executes an ASP and executes a fork_and_buffer call where the parent waits
 * on the ASP and the child to terminate execution while the child returns immediately after the fork_and_buffer call
 * with the read end of the pipe stored in the address pointed to by outfd. This can enable you to chain the
 * execution of several ASPs in sequence without personally maintaining the buffering boilerplate. Returns -2
 * on error before the fork, -1 on error in the parent after the fork, 0 for execution in the child, and >0 in the
 * parent, assuming no errors.
 */
int fork_and_buffer_async_asp(struct asp *asp, const int argc, char *argv[], const int infd, int *outfd)
{
    int rc, status, data[2];
    pid_t pid;

    if(asp == NULL || outfd == NULL || (argv == NULL && argc != 0)) {
        dlog(0, "Inavild arguments provided to function\n");
        return -2;
    }

    rc = pipe(data);
    if(rc < 0) {
        dlog(0, "Unable to create pipe\n");
        return -2;
    }

    /* Cast is justified because arguments are not modified */
    rc = run_asp(asp, infd, data[1], true, argc, argv, data[0], -1);
    close(data[1]);
    if(rc < 0) {
        dlog(0, "Unable to run ASP %s\n", asp->name);
        close(data[0]);
        return -2;
    }

    rc = fork_and_buffer(&pid, outfd, data[0], -1);
    close(data[0]);
    if(rc < 0) {
        dlog(0, "Error in fork and buffer\n");
        stop_asp(asp);
        return -2;
    } else if(rc > 0) {
        rc = wait_asp(asp);
        if(rc < 0) {
            dlog(0, "Error in wait ASP\n");
            return -1;
        }

        rc = waitpid(pid, &status, 0);
        if(rc < 0) {
            /* There's no format specified specifically for PID, so cast to widest
             * integer type */
            dlog(0, "Error in waitpid for PID %ld\n", (long)pid);
            rc = -1;
        } else if(WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            dlog(0, "Child process %ld exited with error code %d\n", (long)pid, WEXITSTATUS(status));
            rc = -1;
        } else {
            rc = 1;
        }
    }

    return rc;
}

/**
 * This function behaves as the fork_and_buffer_async_asp function except, instead of an input
 * file descriptor, the function takes a buffer and a buffer length as an input. The function
 * creates a pipe and, when the ASP is run, the parent writes the input to the pipe and the
 * ASP reads from this pipe. See fork_and_buffer_async_asp for more details.
 */
int fork_and_buffer_async_asp_buffer(struct asp *asp, const int argc,
                                     char *argv[],
                                     const unsigned char *buf_in,
                                     size_t buf_in_len, int timeout,
                                     int *outfd)
{
    int rc         = -1;
    int status     = -1;
    size_t written = -1;
    pid_t pid      = -1;
    int data[2]    = {0};
    int data_in[2] = {0};

    if(asp == NULL || outfd == NULL || (argv == NULL && argc != 0)) {
        dlog(0, "Inavild arguments provided to function\n");
        return -2;
    }

    if (buf_in != NULL) {
      rc = pipe(data_in);
      if(rc < 0) {
        dlog(0, "Unable to create pipe\n");
        return -2;
      }

      rc = maat_io_channel_new(data_in[0]);
      if (rc < 0) {
        dlog(0, "Failure to initialize pipe read end\n");
        close(data_in[0]);
        close(data_in[1]);
        return -2;
      }
      
      rc = maat_io_channel_new(data_in[1]);
      if (rc < 0) {
	dlog(0, "Failure to initialize pipe write end\n");
	close(data_in[0]);
	close(data_in[1]);
	return -2;
      }
    }

    rc = pipe(data);
    if(rc < 0) {
        dlog(0, "Unable to create pipe\n");
        close(data_in[0]);
        close(data_in[1]);
        return -2;
    }

    /* Cast is justified because arguments are not modified */
    if (buf_in != NULL) {
      rc = run_asp(asp, data_in[0], data[1], true, argc, argv, data_in[1], data[0], -1);
      close(data_in[0]);
    } else {
      rc = run_asp(asp, -1, data[1], true, argc, argv, data_in[1], data[0], -1);
    }
    
    close(data[1]);
    if(rc < 0) {
        dlog(0, "Unable to run ASP %s\n", asp->name);
        close(data[0]);
 
	if (buf_in != NULL) {
	  close(data_in[1]);
	}

        return -2;
    }

    /* Write input buffer to the ASP's input */
    if (buf_in != NULL) {
      rc = maat_write_sz_buf(data_in[1], buf_in, buf_in_len,
                           &written, timeout);
      close(data_in[1]);
    }

    if(rc < 0) {
        dlog(0, "Error writing input to channel\n");
        stop_asp(asp);
        return -1;
    }

    rc = fork_and_buffer(&pid, outfd, data[0], -1);
    close(data[0]);
    if(rc < 0) {
        dlog(0, "Error in fork and buffer\n");
        stop_asp(asp);
        return -2;
    } else if(rc > 0) {
        rc = wait_asp(asp);
        if(rc < 0) {
            dlog(0, "Error in wait ASP\n");
            return -1;
        }

        rc = waitpid(pid, &status, 0);
        if(rc < 0) {
            /* There's no format specified specifically for PID, so cast to widest
             * integer type */
            dlog(0, "Error in waitpid for PID %ld\n", (long)pid);
            rc = -1;
        } else if(WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            dlog(0, "Child process %ld exited with error code %d\n", (long)pid, WEXITSTATUS(status));
            rc = -1;
        } else {
            rc = 1;
        }
    }

    return rc;
}
