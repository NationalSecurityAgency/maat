/*
 * Copyright 2023 United States Government
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
#include <errno.h>
#include <string.h>
#include <openssl/x509.h>
#include <syslog.h>
#include <limits.h>
#include <glib.h>

#include <sys/types.h>
#include <unistd.h>

#ifndef __UTIL_H__
#define __UTIL_H__


/*! \file
 * general utility functions for use in the Maat framework.
 */

/* macro used to mark unused attributes to shutup warnings */
#define UNUSED  __attribute__((unused))

typedef char uuid_str_t[37];

extern int __libmaat_debug_level;
extern int __libmaat_syslog;

#ifndef DISABLE_DLOG
#define	dlog(x, fmt, args...) do {					\
		if (x <= __libmaat_debug_level) {			\
			if (__libmaat_syslog) {				\
				syslog(LOG_INFO, "(%4d) [%s:%d]: " fmt, getpid(), \
				       __FUNCTION__, __LINE__, ##args);	\
			} else {					\
				fprintf(stderr, "(%4d) [%16.16s:%d]\t: " fmt, \
					getpid(), __FUNCTION__,__LINE__,##args); \
			}						\
		}							\
	} while(0)
#else
#define dlog(x, fmt, args...) /* nothing */
#endif

#define dperror(str) do { 						\
	dlog(0, "%s: %s\n", str, strerror(errno));			\
	fflush(stdout);							\
} while(0)

void libmaat_init(int syslog, int loglevel);
void libmaat_exit(void);
void libmaat_ssl_exit(void);
void libmaat_ssl_init(void);
void libmaat_xml_exit(void);
void libmaat_xml_init(void);

/**
 * Return the contents of the file @filename in a malloc()'ed
 * buffer. Set *@size to the size of the buffer.
 */
unsigned char *file_to_buffer(const char *filename, size_t *size);

/**
 * Similar to file_to_buffer() but ensures the result is a NULL
 * terminated ASCII string.
 */
char *file_to_string(const char *filename);

/**
 * Return a malloc()ed buffer containing @bytes bytes read from the
 * /dev/urandom device
 */
unsigned char *get_random_bytes(size_t bytes);
unsigned char *gen_nonce_raw(void);
char *gen_nonce_str(void);
char *bin_to_hexstr(const unsigned char *data, size_t len);
unsigned char *hexstr_to_bin(const char *hex_string, size_t len);
char *get_fingerprint(const char *certfile, X509 *x509);
char *find_file_in_dir(const char *dir, const char *pattern);

/**
 * A combination of strlcat and snprintf, perform a formatted print at
 * the end of the string pointed to by @str and return the pointer
 * @str. Assumes that the buffer pointed to by @str is exactly @sz
 * bytes long, if the resulting string (including NULL terminator)
 * would exceed this limit then nothing is written and a NULL pointer
 * is returned. May return NULL if other errors are encountered (I
 * still have no idea what causes snprintf() to fail with an error
 * code, but the manpage says it might, so sncatf() might too).
 */
char *sncatf(char *str, size_t sz, const char *fmt, ...);

/**
 * Construct a path from the varargs (terminated by a NULL argument)
 * in the buffer pointed to be @path of size at most @n. Returns the
 * size of the path generated or -1 if the buffer is not big enough.
 * The returned path is guaranteed to be null terminated.
 */
ssize_t construct_path(char *path, size_t n, char *base, ...);

/**
 * Recursively follow symlinks starting @in until a non-symlink is
 * reached. The final path is placed in the buffer of size @sz pointed
 * to by @out. Returns 0 on success or < 0 on error (notably -EMLINK
 * if too many symlinks are encountered or -EFBIG if a link target is
 * encountered that is larger than @sz).
 *
 * If successful, @out is guaranteed to be a NULL terminated and point
 * to a non-symlink file (up to potential for fs race conditions).
 */
int chase_links(const char *in, char *out, size_t sz);

/**
 * Write @size bytes from @buf to the file @filename. Uses default creation mode of S_IRUSR | S_IWUSR
 */
ssize_t buffer_to_file(const char *filename, const unsigned char *buf, size_t size);

/**
 * Appends @size bytes from @buf to the file @filename. Uses default creation mode of S_IRUSR | S_IWUSR
 */
ssize_t append_buffer_to_file(const char *filename, const unsigned char *buf, size_t size);

/**
 * Write @size bytes from @buf to the file @filename with the given mode (perm = (mode & ~umask)).
 */
ssize_t buffer_to_file_perm(const char *filename, const unsigned char *buf, size_t size, int mode);

/**
 * Write @size bytes from @buf to the file @dir/@file.
 */
ssize_t buffer_to_dir_file(const char *dir, const char *file,
                           const unsigned char *buf, size_t size);

/**
 * Recursively make all directories needed for the path. Like mkdir -p
 *
 * WARNING: this function temporarily mutates the buffer pointed to by
 * @path and thus is not thread safe.
 */
int mkdir_p(char *path, mode_t mode);

/**
 * Recursively make all directories needed for @path excluding the
 * last component.
 *
 * e.g., mkdir_p_containing("/foo/bar/baz") will make "/foo" and
 * "/foo/bar" but not "/foo/bar/baz".  Useful for ensuring the path to
 * a file or symlink exists before attempting to create the file.
 *
 * WARNING: this function temporarily mutates the buffer pointed to by
 * @path and thus is not thread safe.
 */
int mkdir_p_containing(char *path, mode_t mode);

/*
 * Makes a new string which is a copy of str except that the elements at the beginning
 * and end of str are stripped. The elements eligible for stripping are defined by the
 * function fun_ptr, which returns 0 if there is a character that is an unnacceptable
 * character and a non-zero number otherwise
 */
int strip(const char *str, int (*fun_ptr)(int), char **out);

/* Convenient wrapper to strip most common whitespace */
int strip_whitespace(const char *str, char **out);

int rmrf(char *path);
int path_is_reg(const char *filename);
int path_is_dir(const char *dirname);
int path_is_exe(const char *exename);
int file_exists(const char *filename);
char *file_one_line_to_str(const char *filename);
int runcmd(const char *cmd, char **sout, char **serr);

/**
 * glib compatibility functions
 */
#if (GLIB_MAJOR_VERSION == 2 && GLIB_MINOR_VERSION < 32)
void g_queue_free_full(GQueue *queue, GDestroyNotify free_func);
GList *g_list_copy_deep(GList *list, GCopyFunc func, gpointer user_data);
#endif


#ifndef container_of

#ifdef __GNUC__
#define member_type(type, member) __typeof__ (((type *)0)->member)
#else
#define member_type(type, member) const void
#endif

#define container_of(ptr, type, member) ((type *)( \
    (char *)(member_type(type, member) *){ ptr } - offsetof(type, member)))

#endif

#endif /* __UTIL_H__ */
