/*
 * Copyright 2020 United States Government
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

#define _XOPEN_SOURCE 700
#include <config.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <util.h>
#include <dirent.h>
#include <ftw.h>
#include <stdarg.h>
#include <glib.h>
#include <ctype.h>

#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <common/taint.h>
#include <util/validate.h>
#include <limits.h>
#include <stdint.h>


int mkdir_p(char *path, mode_t mode)
{
    if(path == NULL) {
        return -1;
    }
    char *ptr = strchr(path, '/');
    if(ptr == path) {
        ptr = strchr(ptr+1, '/');
    }
    while(ptr != NULL) {
        *ptr = '\0';
        if(mkdir(path, mode) && errno != EEXIST) {
            return -1;
        }
        *ptr = '/';
        ptr = strchr(ptr+1, '/');
    }
    if(mkdir(path, mode) && errno != EEXIST) {
        return -1;
    }
    return 0;
}

int mkdir_p_containing(char *path, mode_t mode)
{
    char *ptr = strrchr(path, '/');
    int rc;
    if(ptr == NULL || ptr == path) {
        return 0;
    }
    *ptr = '\0';
    rc = mkdir_p(path, mode);
    *ptr = '/';
    return rc;
}

ssize_t path_of_fd(int fd, char *buf, size_t bufsize)
{
    char path[PATH_MAX];
    ssize_t res;

    if(((res = snprintf(path, PATH_MAX, "/proc/self/fd/%d", fd)) >= PATH_MAX) ||
            (res < 0) ||
            ((res = readlink(path, buf, bufsize-1)) < 0)) {
        return -1;
    }
    if(res < 0 || (size_t)res == bufsize) {
        return -1;
    }
    buf[res] = '\0';
    return res+1;
}

char *sncatf(char *buf, size_t sz, const char *fmt, ...)
{
    size_t curlen = strlen(buf);
    ssize_t printed;
    va_list ap;
    if(curlen >= sz) {
        /* The string is already longer than the buffer! */
        return NULL;
    }
    va_start(ap, fmt);
    printed = vsnprintf(buf+curlen, sz - curlen, fmt, ap);
    va_end(ap);
    if(printed < 0 || (size_t)printed >= sz - curlen ) {
        return NULL;
    }
    return buf;
}

int chase_links(const char *in, char *out, size_t sz)
{
    struct stat st;
    size_t insz = strlen(in);
    int rc;
    if(insz > SIZE_MAX - 1 || insz+1 > sz) {
        return -ENAMETOOLONG;
    }
    memmove(out, in, insz+1);

    while((rc = lstat(out, &st)) == 0 && S_ISLNK(st.st_mode)) {
        ssize_t read = readlink(out, out, sz);
        if(read < 0) {
            return -1;
        }
        if((size_t)read >= sz) {
            return -ENAMETOOLONG;
        }
        out[read] = '\0';
    }

    return rc;
}

ssize_t construct_path(char *path, size_t space, char *base, ...)
{
    va_list ap;
    char *arg;
    ssize_t used = 0;
    size_t alen;


    if(space >= SSIZE_MAX) {
        path[0] = '\0';
        return -1;
    }

    alen = strlen(base);
    if(alen > space)
        return -1;
    memcpy(path, base, alen);
    used = (ssize_t)alen;

    va_start(ap, base);
    while((arg = va_arg(ap, char*)) != NULL) {
        if(used+1 == (ssize_t)space) {
            path[used-1] = '\0';
            return -1;
        }
        path[used] = '/';
        used+=1;

        alen = strlen(arg);
        if(space - (size_t)used < alen) {
            path[used+1 == (ssize_t)space ? used-1 : used] = '\0';
            return -1;
        }
        memcpy(path+used, arg, alen);
        used  += (ssize_t)alen;
    }
    if(used >= (ssize_t)space) {
        path[space-1] = '\0';
        return -1;
    }

    path[used] = '\0';
    used      += 1;
    return used;
}

ssize_t buffer_to_file(const char *filename, const unsigned char *buf, size_t size)
{
    return buffer_to_file_perm(filename, buf, size, S_IRUSR|S_IWUSR);
}

ssize_t buffer_to_file_perm(const char *filename, const unsigned char *buf,
                            size_t size, int mode)
{
    int fd;
    ssize_t ret;

    if(size > SSIZE_MAX) {
        dlog(0, "Error: can't write more than %zd bytes", (ssize_t) SSIZE_MAX);
        return -1;
    }

    fd = open(filename, O_CREAT|O_WRONLY|O_CLOEXEC, mode);
    if (fd < 0) {
        dperror("Error opening filename");
        return fd;
    }

    ret = write(fd, buf, size);
    if (ret != (ssize_t)size) {
        dlog(6, "only wrote %zd bytes to %s\n", ret, filename);
    }

    close(fd);
    return ret;
}

ssize_t buffer_to_dir_file(const char *dir, const char *file,
                           const unsigned char *buf, size_t size)
{
    char dirfile[PATH_MAX];
    if(snprintf(dirfile, PATH_MAX, "%s/%s", dir, file) >= PATH_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return buffer_to_file(dirfile, buf, size);
}

unsigned char *file_to_buffer(const char *filename, size_t *size)
{
    int fd;
    struct stat stbuf;
    ssize_t ret;
    unsigned char *buf;
    ret = stat(filename, &stbuf);
    if (ret) {
        dlog(6, "stat returned %zd\n", ret);
        return NULL;
    }

    *size = (size_t)stbuf.st_size;
    buf = (unsigned char *)malloc(*size);
    if(buf == NULL) {
        dlog(0,"allocation failed\n");
        return NULL;
    }
    memset(buf, 0, *size);

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        dlog(0, "Error opening file %s\n", filename);
        free(buf);
        return NULL;
    }

    ret = read(fd, buf, *size);
    close(fd);
    if (ret < 0) {
        dlog(0, "read() returned %zd\n", ret);
        free(buf);
        return NULL;
    }

    *size = (size_t)ret;

    return buf;
}

char *file_to_string(const char *filename)
{
    int fd;
    struct stat stbuf;
    ssize_t ret;
    size_t size;
    unsigned char *buf;
    char *strout = NULL;

    ret = stat(filename, &stbuf);
    if (ret) {
        dlog(6, "stat returned %zd\n", ret);
        return NULL;
    }

    size = (size_t)stbuf.st_size;
    if(size == SIZE_MAX) {
        dlog(0, "File of size %zu too big!\n", size);
        return NULL;
    }
    size += 1;

    buf = malloc(size);
    if(buf == NULL) {
        dlog(0, "allocation failed\n");
        return NULL;
    }
    memset(buf, 0, size);

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        dlog(0, "Error opening file %s\n", filename);
        free(buf);
        return NULL;
    }

    ret = read(fd, buf, size-1);
    close(fd);
    if (ret < 0) {
        dlog(0, "read() returned %zd\n", ret);
        free(buf);
        return NULL;
    }
    if((strout = validate_cstring_ascii_len(buf, size)) == NULL) {
        dlog(2, "ASCII string validation of file %s failed\n", filename);
        free(buf);
        return NULL;
    }
    return strout;
}


char *get_fingerprint(const char *certfile, X509 *x509_in)
{
    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned int len = EVP_MAX_MD_SIZE;
    unsigned int i;
    int ret;
    char *fprint;
    FILE *fp;
    X509 *x509;

    if (!x509_in) {
        if (!certfile) {
            dperror("Can't have both filename and x509 = NULL");
            return NULL;
        }

        fp = fopen(certfile, "r");
        if (!fp) {
            dlog(0, "Error opening cert file %s\n", certfile);
            return NULL;
        }
        x509 = PEM_read_X509(fp, NULL, NULL, NULL);
        if (!x509) {
            dlog(0, "Error reading x509 cert from file %s\n", certfile);
            fclose(fp);
            return NULL;
        }
        fclose(fp);
    } else
        x509 = x509_in;

    ret = X509_digest(x509, EVP_sha1(), buf, &len);
    if (ret < 0) {
        dperror("Error from X509 digest");
        return NULL;
    }

    fprint = malloc((len*3)+1);
    if (!fprint) {
        dperror("Error allocating fingerprint string");
        return NULL;
    }

    for (i=0; i<len; i++)
        snprintf(fprint+(i*3), 4, "%02hhX:", buf[i]);

    fprint[(len*3)-1] = 0;

    if (!x509_in)
        X509_free(x509);

    return fprint;
}

/*  returns a buffer of 'bytes' random byted, or NULL on error */
unsigned char *get_random_bytes(size_t bytes)
{
    unsigned char *ret;
    int fd;
    ssize_t rc;

    if(bytes > SSIZE_MAX) {
        dlog(0, "Unable to get more than %zd random bytes at a time\n",
             (ssize_t) SSIZE_MAX);
        return NULL;
    }

    ret = malloc(bytes);
    if (!ret) {
        dperror("Error allocating random bytes");
        return NULL;
    }

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        dperror("Error opening /dev/urandom");
        goto out_error;
    }

    rc = read(fd, ret, bytes);
    if (rc != (ssize_t)bytes) {
        dperror("Error reading from /dev/urandom");
        close(fd);
        goto out_error;
    }
    close(fd);

    /* random bytes are never actually tainted */
    return UNTAINT(ret);

out_error:
    free(ret);
    return NULL;
}

unsigned char *gen_nonce_raw(void)
{
    return get_random_bytes(20);
}

char *bin_to_hexstr(const unsigned char *data, size_t len)
{
    char *ret = NULL;
    size_t strsize = 0;
    size_t i;

    strsize = (len*2)+1;
    ret = malloc(strsize);
    if (!ret) {
        return NULL;
    }

    memset(ret, 0, strsize);
    for (i=0; i<len; i++) {
        snprintf(&ret[i*2], 3, "%02x", data[i]);
    }
    ret[strsize-1] = 0;

    return ret;
}


char *gen_nonce_str(void)
{
    unsigned char *buf;
    char *test;

    buf = gen_nonce_raw();
    if (!buf)
        return NULL;

    test = bin_to_hexstr(buf, 20);

    free(buf);
    return test;
}

/*
 * This function converts a hexidecimal STRING to its original binary form.
 * It is meant to be the opposite of the transformation that gen_nonce_str applies.
 */
unsigned char *hexstr_to_bin(const char *hex_string, size_t len)
{
    unsigned char *test;
    char chars[2];
    int ints[2];
    unsigned int i, j;

    if (hex_string == NULL || len == 0) {
        return NULL;
    }

    test = malloc(len / 2);
    if (!test) {
        dperror("malloc");
        return NULL;
    }

    for (i = 0; i < len; i = i + 2) {
        chars[0] = hex_string[i];
        chars[1] = hex_string[i + 1];

        for (j = 0; j < 2; j++) {
            if (chars[j] >= '0' && chars[j] <= '9')
                ints[j] = (chars[j] - '0');
            else if (chars[j] >= 'A' && chars[j] <= 'F')
                ints[j] = (chars[j] - 'A' + 10);
            else if (chars[j] >= 'a' && chars[j] <= 'f')
                ints[j] = (chars[j] - 'a' + 10);
            else {
                free(test);
                return NULL;
            }
        }
        test[i / 2] = (unsigned char)((ints[0] << 4) + ints[1]);
    }

    return test;
}


/*
 * return the first filename from dir that matches pattern.
 */
char *find_file_in_dir(const char *dir, const char *pattern)
{
    struct dirent *dent;
    DIR *dirp;
    char *buf = NULL;

    if (!pattern || !dir) {
        dlog(1,"an argument is null");
        return NULL;
    }

    dirp = opendir(dir);
    if (!dirp) {
        dperror("Error opening dir");
        return NULL;
    }

    while((dent = readdir(dirp)) != NULL) {
        if (strncmp(dent->d_name, pattern, strlen(pattern))==0) {
            buf = g_strdup_printf("%s/%s", dir, dent->d_name);
            break;
        }
    }

    closedir(dirp);

    return buf;
}

/* POSIX nftw() callback function for removing a directory recursively */
static int remove_callback(const char *fpath,
                           const struct stat UNUSED *sb,
                           int UNUSED typeflag,
                           struct FTW UNUSED *ftwbuf)
{
    int ret = remove(fpath);
    if (ret)
        dperror(fpath);
    return ret;
}

int rmrf(char *path)
{
    return nftw(path, remove_callback, 64, FTW_DEPTH | FTW_PHYS);
}

int file_exists(const char *filename)
{
    int ret;
    struct stat stbuf;

    ret = stat(filename, &stbuf);
    if (ret < 0)
        return 0;
    return 1;
}

int path_is_dir(const char *dirname)
{
    int ret;
    struct stat stbuf;

    ret = stat(dirname, &stbuf);
    if (ret < 0)
        return 0;
    if (!S_ISDIR(stbuf.st_mode))
        return 0;
    return 1;
}

int path_is_reg(const char *filename)
{
    int ret;
    struct stat stbuf;

    ret = stat(filename, &stbuf);
    if (ret < 0)
        return 0;
    if (!S_ISREG(stbuf.st_mode))
        return 0;
    return 1;
}

int path_is_exe(const char *exename)
{
    int ret;
    struct stat stbuf;

    ret = stat(exename, &stbuf);
    if (ret < 0)
        return 0;
    if (!S_ISREG(stbuf.st_mode))
        return 0;
    if (!(stbuf.st_mode & S_IXUSR))
        return 0;
    return 1;
}

char *file_one_line_to_str(const char *filename)
{
    char *rtn = NULL;

    char *buf = file_to_string(filename);
    if(buf) {
        size_t len = 0;
        while (buf[len]!='\n' && buf[len]!='\r' && buf[len]!='\0')
            len++;
        buf[len]='\0';

        rtn = realloc(buf, len+1);
        if(rtn == NULL) {
            dlog(0, "Error, could not realloc\n");
            free(buf);
        }
    }

    return rtn;
}

int runcmd(const char *cmd, char **sout, char **serr)
{
    int ret;
    int errcode;
    int status = 0;
    GError *gerror = NULL;

    ret = g_spawn_command_line_sync(cmd, sout, serr, &status, &gerror);
    if (ret == FALSE) {
        errcode = gerror->code;
        dlog(0,"Error running command '%s': %s\n", cmd, gerror->message);
        g_error_free(gerror);
        return errcode;
    }

    if (WIFEXITED(status))
        return WEXITSTATUS(status);

    return -status;
}

/*
 * Makes a new string which is a copy of str except that elements at the beginning
 * and end of str are stripped. The elements eligible for stripping are defined by the
 * function fun_ptr, which returns 0 if there is a character that is an unnacceptable
 * character and a non-zero number otherwise
 */
int strip(const char *str, int (*fun_ptr)(int), char **out)
{
    size_t str_len;
    char *ptr = (char *)str, *bk, *res;

    if(str == NULL || out == NULL) {
        dlog(2, "One of the pointer arguments was null\n");
        goto err;
    }

    str_len = strlen(str);

    /* Advance in string until a character not accepted by the function is found */
    while(ptr != str + str_len) {
        if((*fun_ptr)(*ptr) == 0) {
            break;
        }

        ptr += 1;
    }

    /* If the pointer reached the end, the whole string is unacceptable characters,
     * just return an empty string */
    if(ptr == str + str_len) {
        res = malloc(1);
        if(res == NULL) {
            dlog(0, "Unable to allocate memory for result buffer\n");
            goto err;
        }

        *res = '\0';

        goto end;
    }

    bk = (char *) (str + str_len - 1);

    while(bk > ptr) {
        if((*fun_ptr)(*bk) == 0) {
            break;
        }

        bk -= 1;
    }

    //Cast to size_t is safe because, by construction, the term can't be negative before cast
    res = malloc((size_t)(bk - ptr + 2));
    if(res == NULL) {
        dlog(0, "Unable to allocate memory for result buffer\n");
        goto err;
    }

    //Cast to size_t is safe because, by construction, the term can't be negative before cast
    memcpy(res, ptr, (size_t)(bk - ptr + 1));
    res[bk - ptr + 1] = '\0';

end:
    *out = res;
    return 0;
err:
    return -1;
}

/* Convenient wrapper to strip to handle most whitespace */
int strip_whitespace(const char *str, char **out)
{
    return strip(str, isspace, out);
}
