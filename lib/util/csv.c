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
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <util/csv.h>
#include <util/util.h>

/**
 * Read a specific line from a CSV file. This line is
 * identified using a key value, which is stored in
 * a specific column (zero indexed). Gives the full
 * line in the out_buf.
 *
 * Returns 0 on success, 1 if the key is not found in
 * the file, and -1 otherwise.
 */
int read_line_csv(const char *filename, const char *key,
                  int key_col, size_t max_line_len, char **out_buf)
{
    int i = 0;
    int ret = 1;
    char *tmp = NULL;
    char *tok;
    char *out;
    char *csv_line;
    FILE *fp;

    if (out_buf == NULL) {
        dlog(1, "Given null argument for out parameter\n");
        return -1;
    }

    if (max_line_len == 0) {
        dlog(1, "Given 0 size for the length of the line from the CSV file\n");
        return -1;
    }

    csv_line = calloc(max_line_len, 1);
    if (csv_line == NULL) {
        dlog(0,
             "Unable to allocate buffer to store csv from file\n");
        return -1;
    }

    fp = fopen(filename, "r");
    if (fp == NULL) {
        dlog(1, "Unable to open CSV file: %s\n", filename);
        free(csv_line);
        return -1;
    }

    while(1) {
        out = fgets(csv_line, max_line_len, fp);
        if (out == NULL) {
            break;
        } else {
            tmp = calloc(strlen(csv_line) + 1, 1);
            if(tmp == NULL) {
                dlog(0, "Unable to allocate return buffer\n");
                ret = -1;
                goto cleanup;
            }

            strcpy(tmp, csv_line);

            tok = strtok(csv_line, ",");
            while(tok != NULL) {
                if(i == key_col && strcmp(key, tok) == 0) {
                    *out_buf = tmp;
                    ret = 0;
                    goto cleanup;
                } else if (i > key_col) {
                    break;
                }

                i += 1;
                tok = strtok(NULL, ",");
            }

            free(tmp);
            i = 0;
            memset(csv_line, 0, max_line_len);
        }
    }

cleanup:
    fclose(fp);
    free(csv_line);
    return ret;
}

/**
 * Read a specific value from a column in a line from a
 * CSV file. The value given back is stored in the column
 * identified in val_col (zero based). Gives the desired
 * value in the out_buf.
 *
 * Returns 0 on success, 1 if the column does not exist
 * in the line, and -1 otherwise.
 */
int get_col_from_csv_line(const char *str, int val_col,
                          size_t max_line_len, char **out_buf)
{
    int i = 0;
    char *cpy;
    char *tmp;
    char *tok;

    if(out_buf == NULL) {
        dlog(1, "Given null string return parameter\n");
        return -1;
    }

    if (max_line_len == 0) {
        dlog(1, "Given 0 size for the length of the line from the CSV file\n");
        return -1;
    }

    cpy = calloc(max_line_len, 1);
    if(cpy == NULL) {
        dlog(0,
             "Unable to allocate buffer to hold CSV line info\n");
        return -1;
    }

    strncpy(cpy, str, max_line_len - 1);

    tok = strtok(cpy, ",");
    while(tok != NULL) {
        if(i == val_col) {
            tmp = calloc(strlen(tok) + 1, 1);
            if(tmp == NULL) {
                dlog(0, "Unable to allocate buffer for token\n");
                free(cpy);
                return -1;
            }

            memcpy(tmp, tok, strlen(tok));

            *out_buf = tmp;
            free(cpy);
            return 0;
        }

        i += 1;
        tok = strtok(NULL, ",");
    }

    free(cpy);
    return 1;
}

/**
 * Read a specific value from a CSV file. The line the
 * value is pulled from is identified using a key value,
 * which is stored in a specific column (zero indexed).
 * The value given back is stored in the column identified
 * in val_col (zero based). Gives the full line in the out_buf.
 *
 * Returns 0 on success, 1 if the key is not found in
 * the file, 2 if the val_col is not in the CSV, and
 * -1 otherwise.
 */
int read_val_csv(const char *filename, const char *key,
                 int key_col, int val_col, size_t max_line_len,
                 char **out_buf)
{
    int ret;
    char *csv_line = NULL;
    char *tmp = NULL;

    if (out_buf == NULL) {
        dlog(1, "Given NULL out buffer\n");
        return -1;
    }

    ret = read_line_csv(filename, key, key_col, max_line_len,
                        &csv_line);
    if (ret != 0) {
        return ret;
    }

    ret = get_col_from_csv_line(csv_line, val_col, max_line_len,
                                &tmp);
    free(csv_line);
    if (ret == 0) {
        *out_buf = tmp;
    } else if (ret == 1) {
        ret = 2;
    }

    return ret;
}

static int append_line_to_file(const char *filename, const char *line)
{
    int ret;
    FILE *fp;

    fp = fopen(filename, "a+");
    if (fp == NULL) {
        dlog(1, "Unable to open the file %s for appending\n", filename);
        return -1;
    }

    ret = fprintf(fp, "%s\n", line);
    if (ret < 0) {
        dlog(1, "Unable to write to file %s\n", filename);
        return -1;
    }

    fclose(fp);
    return 0;
}

/**
 * Append a set of values given to this function into a CSV
 * file. This function will not check that the number of columns
 * is correct, so the caller should ensure that the correct
 * number of columns are being written to.
 *
 * Returns 0 on a successful write and -1 otherwise.
 */
int append_toks_to_csv(const char *filename, int num_strings, ...)
{
    int i;
    int j;
    int ret;
    size_t len;
    char *str;
    char **strs;
    va_list args;

    strs = calloc(num_strings, sizeof(char *));
    if (strs == NULL) {
        ret = -1;
        goto err;
    }

    va_start(args, num_strings);

    for(i = 0; i < num_strings; i++) {
        /* The copying is likely not required, but va_* functions are tricky
           and I do NOT want to be the victim of weird portability issues */
        str = va_arg(args, char *);

        if (str == NULL) {
            ret = -1;
            goto inner_alloc_err;
        }

        len = strlen(str);
        strs[i] = calloc(len + 1, sizeof(char));

        if (strs[i] == NULL) {
            ret = -1;
            goto inner_alloc_err;
        }

        memcpy(strs[i], str, len);
    }

    va_end(args);

    /*
     * This delegation reduces code duplication at the expense of speed.
     * I think this is a worthwhile tradeoff
     */
    ret = append_tok_list_to_csv(filename, num_strings,
                                 (const char **)strs);

inner_alloc_err:
    for(j = 0; j < i; j++) {
        free(strs[j]);
    }

    free(strs);
err:
    return ret;
}

/**
 * Append a set of values given to this function into a CSV
 * file. This function will not check that the number of columns
 * is correct, so the caller should ensure that the correct
 * number of columns are being written to.
 *
 * Returns 0 on success and -1 otherwise.
 */
int append_tok_list_to_csv(const char *filename, int num_strings,
                           const char *strs[])
{
    int i;
    int ret;
    size_t size = 0;
    char *tmp;
    const char *str;
    char *csv_line = NULL;

    for(i = 0; i < num_strings; i++) {
        str = strs[i];

        // Detect overflow in the size
        if(size > (size + strlen(str))) {
            dlog(1, "Full length of the combination of the strings would cause an overflow in realloc\n");
            free(csv_line);
            return -1;
        }

        tmp = realloc(csv_line, size + strlen(str) + 1);
        if(tmp == NULL) {
            dlog(0, "Unable to allocate a new buffer for the csv line\n");
            free(csv_line);
            return -1;
        }
        csv_line = tmp;

        memcpy(csv_line + size, str, strlen(str));
        size += strlen(str);

        if(i + 1 == num_strings) {
            csv_line[size] = '\0';
        } else {
            csv_line[size] = ',';
        }
 
	size += 1;
    }

    ret = append_line_to_file(filename, csv_line);
    free(csv_line);

    return ret;
}
