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
#ifndef __CSV_H__
#define __CSV_H__

/*! \file
 * functions for interacting with a CSV file.
 */

/**
 * Read a specific line from a CSV file. This line is
 * identified using a key value, which is stored in
 * a specific column (zero indexd). Gives the full
 * line in the out_buf.
 *
 * Returns 0 on success, 1 if the key is not found in
 * the file, and -1 otherwise.
 */
int read_line_csv(const char* filename, const char *key,
                  int key_col, size_t max_line_len,
                  char **out_buf);

/**
 * Read a specific value from a CSV file. The line the
 * value is pulled from is identified using a key value,
 * which is stored in a specific column (zero indexd).
 * The value given back is stored in the column identified
 * in val_col (zero based). Gives the full line in the out_buf.
 *
 * Returns 0 on success, 1 if the key is not found in
 * the file, and -1 otherwise.
 */
int read_val_csv(const char *filename, const char *key,
                 int key_col, int val_col, size_t max_line_len,
                 char **out_buf);

/**
 * Read a specific value from a column in a line from a
 * CSV file. The value given back is stored in the column
 * identified in val_col (zero based). Gives the desired
 * value in the out_buf.
 *
 * Returns 0 on success, 1 if the key is not found in
 * the file, and -1 otherwise.
 */
int get_col_from_csv_line(const char *str, int val_col,
                          size_t max_line_len,
                          char **out_buf);

/**
 * Append a set of values given to this function into a CSV
 * file. This function will not check that the number of columns
 * is correct, so the caller should ensure that the correct
 * number of columns are being written to.
 *
 * Returns 0 on success and -1 otherwise.
 */
int append_toks_to_csv(const char *filename, int num_strings, ...);

/**
 * Append a set of values given to this function into a CSV
 * file. This function will not check that the number of columns
 * is correct, so the caller should ensure that the correct
 * number of columns are being written to.
 *
 * Returns 0 on success and -1 otherwise.
 */
int append_tok_list_to_csv(const char *filename, int num_strings,
                           const char *strs[]);

#endif /* __CSV_H__ */
