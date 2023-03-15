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

#define _GNU_SOURCE

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <dirent.h>
#include <regex.h>
#include <signal.h>
#include <limits.h>
#include <inttypes.h>

#include <glib.h>
#include <uuid/uuid.h>

#include <util/util.h>
#include <util/csv.h>
#include <util/keyvalue.h>
#include <util/xml_util.h>

#include <common/apb_info.h>
#include <common/copland.h>
#include <common/measurement_spec.h>
#include <common/asp.h>

#define ERR_BUFF_SZ 100

/**
 * Return the number of instances of a character in a string
 */
static int num_of_char(const char *string, const char ele)
{
    int i = 0;
    char *tmp = (char *)string;

    while(*tmp != '\0') {
        if(*tmp == ele) {
            i += 1;
        }

        tmp += 1;
    }

    return i;
}

/**
 * Given an array of phrase_arg arguments, find the argument with the given name.
 * Returns the index of the argument in the list of arguments or -1 otherwise.
 */
static int find_arg_by_name(const char *name, const phrase_arg **args, const int num_ele)
{
    int i;

    for(i = 0; i < num_ele; i++) {
        if(args[i]->name && strcmp(args[i]->name, name) == 0) {
            return i;
        }
    }

    return -1;
}

/**
 * Splits a Copland phrase and arguments of the form
 *
 * term[:arg1=value1,arg2=value2,...,argN=valueN]
 *
 * Along the colon (:) delimiter and returns the two in newly-allocated
 * char *s to the caller in the phrase and args parameters, respectively.
 * The memory held by these parameters must be freed by the caller.
 * Args are optional; if the colon is omitted, this parameter will be set
 * to NULL.
 *
 * Returns 0 on success or -1 otherwise.
 */
static int split_copland(const char *phrase_and_args, char **phrase, char **args)
{
    char *str, *str_phr, *str_args, *phr, *arg_list, *lock;

    if(phrase == NULL || args == NULL || phrase_and_args == NULL) {
        dlog(1, "One of the arguments is NULL\n");
        return -1;
    }

    str = strdup(phrase_and_args);
    if(str == NULL) {
        dlog(0, "Unable to allocate memory for Copland phrase copy\n");
        goto err;
    }

    str_phr = strtok_r(str, ":", &lock);
    str_args = strtok_r(NULL, ":", &lock);

    phr = strdup(str_phr);
    if(phr == NULL) {
        dlog(0, "Unable to allocate memory for phrase\n");
        goto phr_alloc_err;
    }

    if(str_args != NULL) {
        arg_list = strdup(str_args);

        if(arg_list == NULL) {
            dlog(0, "Unable to allocate memory for argument list\n");
            goto args_alloc_err;
        }
    } else {
        arg_list = NULL;
    }

    *phrase = phr;
    *args = arg_list;

    free(str);

    return 0;

args_alloc_err:
    free(phr);
phr_alloc_err:
    free(str);
err:
    *phrase = NULL;
    *args = NULL;
    return -1;
}

/*
 * Convert the arguments in a Copland phrase to their string representation.
 * Returns 0 on success or a non-zero quantity otherwise.
 */
int copland_args_to_string(const phrase_arg **args, const int num_args, char **str)
{
    int int_val, i;
    unsigned int dig;
    size_t loc = 0, name_sz, arg_sz;
    char *tmp = NULL, *arg_val = NULL;
    char *scratch = NULL;

    if(str == NULL) {
        dlog(1, "The location to store the result of the parsing is null\n");
        goto err;
    }

    if(num_args <= 0) {
        dlog(3, "There are no arguments to be parsed\n");
        *str = NULL;
        return 0;
    }

    if(args == NULL) {
        dlog(1, "The arguments to be parsed are null\n");
        goto err;
    }

    for(i = 0; i < num_args; i++) {
        switch(args[i]->type) {
        case PLACE:
        case STRING:
            arg_val = strdup((char *)args[i]->data);
            if(arg_val == NULL) {
                dlog(0, "Unable to allocate data for a string argument copy\n");
                goto arg_alloc_err;
            }

            break;
        case INTEGER:
            int_val = *((int *)args[i]->data);

            if(asprintf(&arg_val, "%d", int_val) < 0) {
                dlog(1, "Unable to convert integer to string\n");
                goto arg_parse_err;
            }

            break;
        default:
            dlog(1, "Unknown argument type\n");
            goto err;
        }

        /* Must add memory to string to account for new argument:
           <name>=<value>, and the phrase either ends with a null
           byte or a comma depending on if it is the last argument */
        name_sz = strlen(args[i]->name);
        arg_sz = strlen(arg_val);

        scratch = realloc(tmp, name_sz + arg_sz + 2 + loc);
        if(scratch == NULL) {
            free(arg_val);
            free(tmp);
            goto err;
        }
        tmp = scratch;

        memcpy(tmp + loc, args[i]->name, name_sz);
        loc += name_sz;

        tmp[loc] = '=';
        loc += 1;

        memcpy(tmp + loc, arg_val, arg_sz);
        loc += arg_sz;

        if(i == num_args - 1) {
            tmp[loc] = '\0';
        } else {
            tmp[loc] = ',';
            loc += 1;
        }

        free(arg_val);
    }

    *str = tmp;
    return 0;

arg_parse_err:
    free(arg_val);
arg_alloc_err:
    free(tmp);
err:
    return -1;
}

/*
 * Convert a Copland phrase to a Copland string representation.
 * Return 0 on success and -1 otherwise
 */
int copland_phrase_to_string(const copland_phrase *copl, char **str)
{
    int err = -1;
    size_t phr_len, arg_len;
    char *tmp = NULL, *args = NULL;

    if(str == NULL || copl == NULL) {
        dlog(1, "Null argument provided\n");
        goto end;
    }

    if(copl->num_args == 0) {
        tmp = strdup(copl->phrase);
        if(tmp == NULL) {
            dlog(0, "Unable to allocate buffer for copland string\n");
            goto end;
        }

        *str = tmp;
        return 0;
    }

    if(copland_args_to_string((const phrase_arg **)copl->args, copl->num_args, &args) < 0) {
        dlog(2, "Unable to convert copland arguments as string for phrase %s\n", copl->phrase);
        goto end;
    }

    phr_len = strlen(copl->phrase);
    if(args != NULL) {
        arg_len = strlen(args);
    } else {
        arg_len = 0;
    }

    tmp = malloc(phr_len + arg_len + 2);
    if(tmp == NULL) {
        dlog(0, "Unable to allocate memory for copland string\n");
        goto end;
    }

    memcpy(tmp, copl->phrase, phr_len);
    if(arg_len > 0) {
        tmp[phr_len] = ':';
        memcpy(tmp + phr_len + 1, args, arg_len);
        tmp[phr_len + 1 + arg_len] = '\0';
    } else {
        tmp[phr_len] = '\0';
    }

    free(args);

    err = 0;
    *str = tmp;

end:
    return err;
}

/**
 * Determine if a string argument of a phrase matches the template provided.
 * This is currently implemented as a regex match on the argument contained
 * in the template.
 * Returns 0 if there's a match, a non-zero otherwise
 */
static int eval_str_bounds(const char *str, const char *template_str)
{
    int err = 0;
    char err_buff[ERR_BUFF_SZ];
    regex_t reg;

    if(str == NULL || template_str == NULL) {
        dlog(2, "Given null argument to evaluate\n");
        err = -1;
        goto end;
    }

    err = regcomp(&reg, template_str, REG_EXTENDED);
    if(err) {
        dlog(0, "Unable to compile the expresion given as an argument\n");
        goto end;
    }

    err = regexec(&reg, str, 0, NULL, 0);
    if(err == REG_NOMATCH) {
        dlog(3, "Argument %s not within the bounds defined by %s\n", str, template_str);
    } else if(err != 0) {
        regerror(err, &reg, err_buff, ERR_BUFF_SZ);
        dlog(1, "Regex error: %s\n", err_buff);
    }

    regfree(&reg);
end:
    return err;
}

int eval_bounds_of_args(const copland_phrase *phr, const copland_phrase *bounder)
{
    int err = 0, i;
    phrase_arg *phr_arg, *bou_arg;

    if(phr == NULL || bounder == NULL) {
        dlog(1, "One of the required arguments is NULL\n");
        return -1;
    }

    /* Make sure phr and bounder use the same basic Copland phrase */
    err = strcmp(phr->phrase, bounder->phrase);
    if(err != 0) {
        dlog(3, "Phrase %s did not match bounder: %s\n", phr->phrase,
             bounder->phrase);
        goto end;
    }

    /* Make sure phr and bounder use the same number of args */
    err = phr->num_args - bounder->num_args;
    if(err != 0) {
        dlog(3, "Number of arguments did not match\n");
        goto end;
    }

    /* For each argument of phr and bounder, check that
     * they have the same name and type, and that the
     * value held by the data of phr is within the bounds
     * specified by the data attribute of bound.
     */
    for(i = 0; i < phr->num_args; i++) {
        phr_arg = phr->args[i];
        bou_arg = bounder->args[i];

        err = strcmp(phr_arg->name, bou_arg->name);
        if(err != 0) {
            dlog(3, "Argument names did not match\n");
            goto end;
        }

        if(phr_arg->type != bou_arg->type) {
            dlog(3, "Argument type didn't match\n");
            goto end;
        }

        switch(phr_arg->type) {
        case STRING:
            err = eval_str_bounds((const char *)phr_arg->data, (const char *)bou_arg->data);
            break;
        case PLACE:
            err = strcmp(phr_arg->data, bou_arg->data);
            break;
        case INTEGER:
            err = memcmp(phr_arg->data, bou_arg->data, sizeof(int));
            break;
        default:
            dlog(1, "Unrecognized argument type %d\n", phr_arg->type);
            goto end;
        }

        if(err != 0) {
            goto end;
        }
    }

end:
    return err;
}

/*
 * Copy the phrases from phrs that are bounded by a Copland Phrase in bounders
 * into a new list. Returns 0 on success and -1 otherwise.
 */
int copy_bounded_phrases(const GList *phrs, const GList *bounders, GList **out)
{
    GList *l, *j, *tmp = NULL;
    copland_phrase *phr, *bounder, *copy;

    if(out == NULL) {
        dlog(1, "The memory location to place the copy is NULL");
        return -1;
    }

    if(phrs == NULL) {
        dlog(3, "No phrases provided, output is trivially null\n");
        *out = NULL;
        return 0;
    }

    if(bounders == NULL) {
        dlog(1, "Null list of bounding \"filter\" phrases to pick from\n");
        return -1;
    }

    *out = NULL;

    for(l = (GList *)phrs; l && l->data; l = g_list_next(l)) {
        phr = (copland_phrase *)l->data;
        bounder = NULL;

        for(j = (GList *)bounders; j && j->data; j = g_list_next(j)) {
            bounder = (copland_phrase *)j->data;

            if(eval_bounds_of_args(phr, bounder) == 0) {
                break;
            }
        }

        /* If j is non-null, the loop did not end because the end of the list
           was reached, which means if found a bounder for the phrase */
        if(j) {
            if(deep_copy_copland_phrase(phr, &copy) != 0) {
                g_list_free_full(tmp, (GDestroyNotify)free_copland_phrase_glist);
                return -1;
            }
            tmp = g_list_append(tmp, copy);
        }
    }

    *out = tmp;

    return 0;
}

/*
 * Given a copland phrase and a list of Copland Phrases, verify that the Copland Phrase is
 * represented by some member of the list and that the arguments are properly bounded.
 * Returns 0 on success and a non-zero number otherwise.
 */
int match_phrase(const copland_phrase *phr, const GList *phrases, copland_phrase **match)
{
    GList *a;
    struct phrase_meas_spec_pair *pair;

    if(phr == NULL || phrases == NULL || match == NULL) {
        dlog(2, "Null argument provided\n");
        return -1;
    }

    for(a = (GList *) phrases; a && a->data; a = g_list_next(a)) {
        pair = (struct phrase_meas_spec_pair *)a->data;

        if(eval_bounds_of_args(phr, pair->copl) == 0) {
            *match = pair->copl;
            return 0;
        }
    }

    return -1;
}

/**
 * Copy the information contained in an argument phrase into a new
 * struct. Return 0 if the argument is successfully copied, -1 otherwise
 */
static int copy_copland_arg(const phrase_arg *arg, phrase_arg **copy)
{
    phrase_arg *tmp = NULL;

    if(arg == NULL || copy == NULL) {
        dlog(2, "Provided null arguments\n");
        goto err;
    }

    tmp = malloc(sizeof(phrase_arg));
    if(tmp == NULL) {
        dlog(0, "Unable to allocate memory for phrase_arg copy\n");
        goto err;
    }
    memset(tmp, 0, sizeof(phrase_arg));

    tmp->type = arg->type;

    tmp->name = malloc(strlen(arg->name) + 1);
    if(tmp->name == NULL) {
        dlog(0, "Unable to allocate memory for phrase_arg name\n");
        goto err;
    }
    strcpy(tmp->name, arg->name);

    if(arg->data != NULL) {
        switch(tmp->type) {
        case PLACE:
        case STRING:
            tmp->data = malloc(strlen((char *)arg->data) + 1);
            if(tmp->data == NULL) {
                dlog(0, "Unable to allocate memory for argument data\n");
                goto err;
            }

            strcpy(tmp->data, (char *)arg->data);
            break;
        case INTEGER:
            tmp->data = malloc(sizeof(int));
            if(tmp->data == NULL) {
                dlog(0, "Unable to allocate memory for argument data\n");
                goto err;
            }

            *((int *)tmp->data) = *((int *)arg->data);
            break;
        default:
            dlog(1, "Unknown argument type %d\n", tmp->type);
            goto err;
        }
    } else {
        tmp->data = NULL;
    }

    *copy = tmp;
    return 0;

err:
    if(tmp != NULL) {
        free(tmp->name);
        free(tmp->data);
        free(tmp);
    }

    return -1;
}

/*
 * Creates a deep copy of the phrase. Returns 0 on success and -1 otherwise.
 */
int deep_copy_copland_phrase(const copland_phrase *phrase, copland_phrase **copy)
{
    int i = 0;
    int j, err;
    copland_phrase *tmp = NULL;

    if(phrase == NULL || copy == NULL) {
        dlog(2, "Provided null argument\n");
        goto err;
    }

    tmp = malloc(sizeof(copland_phrase));
    if(tmp == NULL) {
        dlog(0, "Unable to allocate memory for copy\n");
        goto err;
    }
    memset(tmp, 0, sizeof(copland_phrase));

    tmp->role = phrase->role;
    tmp->num_args = phrase->num_args;

    tmp->phrase = malloc(strlen(phrase->phrase) + 1);
    if(tmp->phrase == NULL) {
        dlog(0, "Unable to allocate memory for phrase copy\n");
        goto err;
    }
    strcpy(tmp->phrase, phrase->phrase);

    if(tmp->num_args > 0) {
        /* Coercion justified because number of arguments must be positive */
        tmp->args = malloc(sizeof(phrase_arg *) * (unsigned int)tmp->num_args);
        if(tmp->args == NULL) {
            dlog(0, "Unable to allocate memory for args copy\n");
            goto err;
        }

        while(i < tmp->num_args) {
            err = copy_copland_arg(phrase->args[i], &tmp->args[i]);
            if(err < 0) {
                dlog(1, "Unable to copy argument %s\n", phrase->args[i]->name);
                goto err;
            }

            i += 1;
        }
    } else {
        tmp->args = NULL;
    }

    *copy = tmp;
    return 0;

err:
    if(tmp != NULL) {
        free(tmp->phrase);

        for(j = 0; j < i; j++) {
            free_phrase_arg(tmp->args[j]);
        }

        free(phrase->args);

        free(tmp);
    }

    return -1;
}

/**
 * Searches the GList of copland_phrase structs provided in phrase_pairs for
 * a template that is applicable to the passed copland phrase.
 *
 * If template is not NULL, a pointer to the selected template is returned to
 * to the caller via this argument.
 *
 * Returns 0 if an applicable template is found without error and -1 otherwise.
 */
static int find_copland_template(const char *phrase, const GList *phrase_pairs,
                                 struct phrase_meas_spec_pair **template)
{
    int num_args, res = 0;
    char *phr, *args;
    struct phrase_meas_spec_pair *pair;
    GList *a;

    /* Get the number of arguments of the Copland phrase  */
    res = split_copland(phrase, &phr, &args);
    if(res < 0) {
        dlog(2, "Unable to split phrase into phrase and args\n");
        goto end;
    }

    if(args != NULL) {
        num_args = num_of_char(args, '=');
    } else {
        num_args = 0;
    }

    for(a = (GList *)phrase_pairs; a && a->data; a = a->next) {
        pair = (struct phrase_meas_spec_pair *)a->data;

        dlog(6, "COMPARING %s:%s / %d:%d in find_copland_template\n", phr, pair->copl->phrase, num_args, pair->copl->num_args);

        if(strcmp(pair->copl->phrase, phr) == 0 && num_args == pair->copl->num_args) {
            if(template != NULL) {
                *template = pair;
            }

            goto free_info;
        }
    }

    res = -1;

free_info:
    free(phr);
    free(args);
end:
    return res;
}

/**
 * Parse an argument with relation to a template. Returns -1 on failure or a 0 on success.
 */
static int parse_phrase_arg(const phrase_arg *template,
                            const char *name, const void *value,
                            phrase_arg **to_parse)
{
    long int store = 0;
    int *val = NULL;
    char *pt = NULL;
    phrase_arg *tmp = NULL;

    if(name == NULL || template == NULL ||
            template->name == NULL || value == NULL) {
        dlog(2, "Null arguments given\n");
        return -1;
    }

    if(strcmp(name, template->name)) {
        dlog(2, "Argument does not match the template\n");
        return -1;
    }

    tmp = malloc(sizeof(phrase_arg));
    if(tmp == NULL) {
        dlog(0, "Unable to allocate memory for argument\n");
        return -1;
    }
    memset(tmp, 0, sizeof(phrase_arg));

    /* TODO: Implement ability for template to specify/check bounds here*/
    switch(template->type) {
    case INTEGER:
        errno = 0;
        store = strtol((const char *)value, &pt, 10);
        if(errno || *pt != '\0' || store > INT_MAX || store < INT_MIN) {
            dlog(1, "Warning: Integer argument could not be parsed\n");
            goto bounds_err;
        }

        val = malloc(sizeof(int));
        if(val == NULL) {
            dlog(0, "Unable to allocate memory\n");
            goto bounds_err;
        }

        *val = store;

        tmp->data = (void *)val;
        tmp->type = INTEGER;
        break;
    case PLACE:
        errno = 0;
        store = strtol((const char *)value, &pt, 10);
        if(errno || *pt != '\0' || store > INT_MAX || store < 0) {
            dlog(1, "Warning: Place argument could not be parsed\n");
            goto bounds_err;
        }

        tmp->data = strdup((void *)value);
        if(tmp->data == NULL) {
            dlog(0, "Unable to allocate memory for copy of domain value\n");
            goto bounds_err;
        }

        tmp->type = PLACE;
        break;
    case STRING:
        tmp->data = strdup((char *)value);
        if(tmp->data == NULL) {
            dlog(0, "Unable to allocate memory for copy of string value\n");
            goto bounds_err;
        }

        tmp->type = STRING;
        break;
    default:
        dlog(1, "Unknown template type %d\n", template->type);
        goto bounds_err;
    }

    tmp->name = strdup(name);

    *to_parse = tmp;
    return 0;

bounds_err:
    free(tmp);
    free(val);

    return -1;
}

/**
 * Parse the arguments for a Copland Phrase with respect to a template and place the arguments
 * within the copland_phrase tmp. Returns 0 on success or -1 otherwise
 */
static int parse_phrase_args(const char *args,
                             const copland_phrase *template,
                             copland_phrase *tmp)
{
    int err = 0, idx;
    char *str = NULL;
    char *tok, *hay, *var, *var_name, *var_val, *out, *in;
    phrase_arg **phrase_args = NULL;
    phrase_arg **new_phrase_args;

    if(template == NULL || template->role != BASE) {
        dlog(1, "Invalid arguments passed to the function\n");
        return -1;
    }

    tmp->num_args = 0;

    if(args == NULL) {
        dlog(6, "No arguments to parse for phrase\n");
        goto skip_args;
    }

    str = strdup(args);
    if(str == NULL) {
        dlog(0, "Cannot allocate memory for temporary data\n");
        goto error;
    }

    /* Keeping track of str to free the string later */
    hay = str;

    /* Assume arguments are comma seperated - change if this assumption no longer holds */
    while((tok = strtok_r(hay, ",", &out))) {
        /* Type coercion us justified because this is known to be non-zero */
        new_phrase_args = realloc(phrase_args, (unsigned long)(tmp->num_args + 1) * sizeof(phrase_arg *));
        if(new_phrase_args == NULL) {
            dlog(0, "Unable to allocate memory for copland arguments\n");
            goto error;
        }
        phrase_args = new_phrase_args;

        if(tmp->num_args >= template->num_args) {
            dlog(2, "Warning: The copland phrase has more arguments than the template!\n");
            goto error;
        }

        var = strdup(tok);
        if(var == NULL) {
            dlog(0, "Cannot allocate memory for copy of variable");
            goto error;
        }

        var_name = strtok_r(var, "=", &in);
        var_val = strtok_r(NULL, "=", &in);

        if(var_val == NULL) {
            dlog(2, "Argument %s is not formatted correctly, must be <var_name>=<var_value>\n", var_name);
            free(var);
            goto error;
        }

        idx = find_arg_by_name(var_name, (const phrase_arg **)
                               template->args,
                               template->num_args);

        if(idx < 0) {
            dlog(1, "Argument of the name %s not found\n", var_name);
            free(var);
            goto error;
        }

        err = parse_phrase_arg(template->args[idx], var_name,
                               var_val,
                               &phrase_args[tmp->num_args]);
        if(err < 0) {
            dlog(1, "Unable to parse argument %s=%s \n", var_name, var_val);
            free(var);
            goto error;
        }

        free(var);
        tmp->num_args += 1;
        hay = NULL;
    }

skip_args:
    /* Only give a correct parse if the same number of arguments are given */
    if(tmp->num_args == template->num_args) {
        tmp->args = phrase_args;
        free(str);
        return tmp->num_args;
    }

error:
    for (idx = 0; idx < tmp->num_args; idx++) {
        free_phrase_arg(phrase_args[idx]);
    }
    tmp->num_args = -1;
    free(str);
    free(phrase_args);
    return -1;
}

/*
 * Given a list of arguments, parse a list of the arguments and their names as
 * Key Value pairs. Return the number of parsed arguments or < 0 on error
 */
int parse_copland_args_kv(const char *args, struct key_value ***arg_list)
{
    int res;
    size_t i = 0, j;
    char *tmp_args, *full_arg, *arg_lock, *eq_lock, *tmp_key, *tmp_val, *arg_holder;
    char *arg = NULL;
    struct key_value **kv_list;

    res = num_of_char(args, '=');
    if (res <= 0) {
        dlog(3, "Warning: No args to parse or arguments are in incorrect format\n");
        *arg_list = NULL;
        return 0;
    }

    /* Coercion is justified because, due to the above conditional, the int must be
     * non-negative */
    kv_list = malloc(sizeof(struct key_value *) * (unsigned long) res);
    if(kv_list == NULL) {
        dlog(0, "Unable to allocate memory for key value list\n");
        goto kv_alloc_err;
    }

    tmp_args = strdup(args);
    if(tmp_args == NULL) {
        dlog(0, "Unable to allocate memory for working arg list\n");
        goto tmp_args_alloc_err;
    }
    arg_holder = tmp_args;

    while((full_arg = strtok_r(tmp_args, ",", &arg_lock))) {
        arg = strdup(full_arg);
        if(arg == NULL) {
            dlog(0, "Unable to allocate memory to duplicate argument\n");
            goto arg_alloc_err;
        }

        kv_list[i] = malloc(sizeof(struct key_value));
        if(kv_list[i] == NULL) {
            dlog(0, "Unable to allocate memory for key value element\n");
            goto kv_ele_alloc_err;
        }

        i += 1;

        tmp_key = strtok_r(arg, "=", &eq_lock);
        tmp_val = strtok_r(NULL, "=", &eq_lock);

        if(tmp_key == NULL || tmp_val == NULL) {
            dlog(1, "Invalid argument provided to APB\n");
            goto kv_parse_err;
        }

        kv_list[i - 1]->key = strdup(tmp_key);
        if(kv_list[i- 1]->key == NULL) {
            dlog(0, "Unable to allocate memory for key string\n");
            goto key_parse;
        }

        kv_list[i - 1]->value = strdup(tmp_val);
        if(kv_list[i - 1]->value == NULL) {
            free(kv_list[i - 1]->key);
            dlog(0, "Unable to allocate memory for value string\n");
            goto val_parse;
        }

        free(arg);
        arg = NULL;
        tmp_args = NULL;
    }

    if(arg_list != NULL) {
        *arg_list = kv_list;
    } else {
        dlog(2, "Given NULL arg_list argument\n");
        goto null_err;
    }

    return res;

null_err:
val_parse:
key_parse:
kv_parse_err:
kv_ele_alloc_err:
    for(j = 0; j < i; j++) {
        free(kv_list[j]);
    }
    free(arg);
arg_alloc_err:
    free(arg_holder);
tmp_args_alloc_err:
    free(kv_list);
kv_alloc_err:
    return -1;
}


/*
 * Uses the passed template to parse the passed phrase and
 * args into a copland phrase struct
 */
int parse_copland_phrase(const char *phrase, const char *args,
                         const copland_phrase *template,
                         copland_phrase **parsed)
{
    int res = 0;
    copland_phrase *tmp;

    if(phrase == NULL || template == NULL || parsed == NULL) {
        dlog(1, "Null argument provided to function\n");
        return -1;
    }

    /*Check to make sure the template struct is of the right type*/
    if(template->role != BASE) {
        dlog(2, "Provided copland phrase template that is not actually a template");
        return -1;
    } else if(strcmp(template->phrase, phrase)) {
        dlog(2, "Not parsing the phrase using the correct template\n");
        return -1;
    }

    tmp = malloc(sizeof(copland_phrase));
    if(!tmp) {
        dlog(0, "Unable to allocate memory for copland phrase\n");
        goto err;
    }

    tmp->num_args = 0;

    tmp->phrase = strdup(phrase);
    if(tmp->phrase == NULL) {
        goto phr_all_err;
    }

    tmp->role = ACTUAL;

    res = parse_phrase_args(args, template, tmp);
    if(res < 0) {
        dlog(0, "Unable to parse arguments in copland phrase %s\n", phrase);
        goto arg_err;
    }

    *parsed = tmp;

    return 0;

arg_err:
phr_all_err:
    free_copland_phrase(tmp);
err:
    return -1;
}

/*
 * Given a phrase of form <phrase>:<comma-delimited-list-of-args> (the latter
 * is optional), parse into a copland phrase struct
 */
int parse_copland_from_pair_list(const char *phrase_and_args, const GList *phrase_pairs, copland_phrase **phrase)
{
    int err;
    char *phr, *args;
    struct phrase_meas_spec_pair *template;

    if(phrase_and_args == NULL || phrase_pairs == NULL || phrase == NULL) {
        dlog(2, "Provided Null argument\n");
        return -1;
    }
    *phrase = NULL;

    err = find_copland_template(phrase_and_args, phrase_pairs, &template);
    if(err < 0) {
        return -1;
    }

    err = split_copland(phrase_and_args, &phr, &args);
    if(err < 0) {
        free_phrase_meas_spec_pair(template);
        dlog(4, "Warning: Unable to match provided Copland Phrase to format: %s\n", phrase_and_args);
        return -1;
    }

    dlog(6, "ARGS ARE: %s\n", args);

    err = parse_copland_phrase(phr, args, template->copl, phrase);
    free(phr);
    free(args);
    return err;
}

/*
 * Parse the Copland Phrase with respect to a list of APBs which contain Copland Phrase templates.
 * Returns 0 if the phrase can be parsed or -1 otherwise.
 */
int parse_copland_from_apb_list(const char *phrase_and_args, const GList *apbs, copland_phrase **phrase)
{
    struct apb *apb;
    GList *l;

    if(phrase == NULL || phrase_and_args == NULL || apbs == NULL) {
        dlog(1, "Null argument provided\n");
        return -1;
    }

    dlog(6, "Parsing Copland phrase: %s\n", phrase_and_args);

    for(l = (GList *) apbs; l && l->data; l = g_list_next(l)) {
        apb = (struct apb *)l->data;

        if(parse_copland_from_pair_list(phrase_and_args, apb->phrase_specs, phrase) == 0) {
            return 0;
        }

    }

    dlog(3, "Error: Unable to find the Copland phrase \"%s\" from the APBs provided\n", phrase_and_args);
    return -1;
}


/*
 * Free the memory associated with a phrase arg
 */
void free_phrase_arg(phrase_arg *arg)
{
    if(arg == NULL) {
        return;
    }

    free(arg->data);
    free(arg->name);
    free(arg);
}

/*
 * Free the memory associated with a copland phrase struct
 */
void free_copland_phrase(copland_phrase *phrase)
{
    int i;

    if(phrase == NULL) {
        return;
    }

    for(i = 0; i < phrase->num_args; i++) {
        free_phrase_arg(phrase->args[i]);
    }

    if(phrase->num_args > 0) {
        free(phrase->args);
    }

    free(phrase->phrase);
    free(phrase);
}

/*
 * Frees the memory associated with a single Copland Phrase
 * Used for GLists to satisfy the demands of their signature
 */
void free_copland_phrase_glist(void *phrase)
{
    copland_phrase *copl = (copland_phrase *)phrase;

    free_copland_phrase(copl);
}

/*
 * Frees the memory associated with a phrase_meas_spec_pair
 */
void free_phrase_meas_spec_pair(struct phrase_meas_spec_pair *pair)
{

    if(pair != NULL) {
        free_copland_phrase(pair->copl);
    }

    free(pair);
}

/**
 * Given an entry describing a place and the data needed regarding that place,
 * parse the information into the place_perms struct. Returns 0 on success and
 * -1 otherwise.
 */
int parse_place_entry(xmlDocPtr doc, xmlNode *place_entry, place_perms **place)
{
    int ret;
    char *name, *info, *unstripped, *stripped;
    xmlNode *entry;
    place_perms *tmp;

    if(place_entry == NULL) {
        dlog(1, "Given null argument\n");
        return -1;
    }

    tmp = calloc(1, sizeof(place_perms));
    if(!tmp) {
        dlog(0, "Unable to allocate memory for place_perms");
        goto tmp_alloc_err;
    }

    unstripped = xmlGetPropASCII(place_entry, "id");
    if(unstripped == NULL) {
        dlog(1, "Cannot read name of places argument\n");
        goto name_err;
    }

    ret = strip_whitespace(unstripped, &stripped);
    free(unstripped);
    if (ret) {
        dlog(2, "Cannot strip whitespace from argument name\n");
        goto name_err;
    }

    tmp->id = stripped;
    if (!tmp->id) {
        dlog(0, "No name given to argument\n");
        goto name_alloc_err;
    }

    for(entry = place_entry->children; entry; entry = entry->next) {
        name = validate_cstring_ascii(entry->name, SIZE_MAX);

        if(entry->type != XML_ELEMENT_NODE || name == NULL) {
            dlog(3, "Unable to parse argument entry\n");
            continue;
        }

        if(strcmp(name, "info") == 0) {
            /* String buffer of characters, so type coercion is justified */
            unstripped = (char *)xmlNodeListGetString(doc, entry->xmlChildrenNode, 1);
            if (unstripped == NULL) {
                dlog(3, "Unable to get info permission from Copland section\n");
                continue;
            }

            ret = strip_whitespace(unstripped, &info);
            free(unstripped);
            if (ret) {
                dlog(2, "Unable to strip whitespace from info permission in Copland section\n");
                continue;
            }

            /* Determine what info permission we're given over this place */
            if(strcmp(info, "host") == 0) {
                tmp->perms |= COPLAND_PLACE_ADDR_PERM;
            } else if(strcmp(info, "port") == 0) {
                tmp->perms |= COPLAND_PLACE_PORT_PERM;
            } else if(strcmp(info, "kernel") == 0) {
                tmp->perms |= COPLAND_PLACE_KERN_PERM;
            } else if(strcmp(info, "domain") == 0) {
                tmp->perms |= COPLAND_PLACE_DOM_PERM;
            } else {
                dlog(1, "Warning: encountered unexpected info type %s in info block\n", info);
            }

            free(info);
        } else {
            dlog(1, "Warning: encountered unexpected element %s in info block\n", name);
            continue;
        }
    }

    *place = tmp;
    return 0;

name_err:
name_alloc_err:
    free(tmp);
tmp_alloc_err:
    return -1;
}

/**
 * Given an entry describing an argument of a copland phrase,
 * parse the information into a phrase_arg. Returns 0 on success
 * and -1 otherwise.
 *
 * XXX: in a future enhancement, the values section will contain
 * constraints on acceptable argument values, which will need to be
 * parsed into phrase->data.
 */
int parse_arg_entry(xmlDocPtr doc, xmlNode *arg_entry, phrase_arg **arg)
{
    int ret;
    char *name, *type, *unstripped, *stripped;
    xmlNode *entry;
    phrase_arg *tmp;

    if(arg_entry == NULL) {
        dlog(1, "Given null argument\n");
        return -1;
    }

    tmp = malloc(sizeof(phrase_arg));
    if(!tmp) {
        dlog(0, "Unable to allocate memory for phrase_arg");
        goto tmp_alloc_err;
    }
    memset(tmp, 0, sizeof(phrase_arg));

    tmp->data = NULL; // Necessary until we implement values below

    unstripped = xmlGetPropASCII(arg_entry, "name");
    if(unstripped == NULL) {
        dlog(1, "Cannot read name of Copland argument\n");
        goto name_err;
    }

    ret = strip_whitespace(unstripped, &stripped);
    free(unstripped);
    if (ret) {
        dlog(2, "Cannot strip whitespace from argument name\n");
        goto name_err;
    }

    tmp->name = stripped;
    if (!tmp->name) {
        dlog(0, "No name given to argument\n");
        goto name_alloc_err;
    }

    for(entry = arg_entry->children; entry; entry = entry->next) {
        name = validate_cstring_ascii(entry->name, SIZE_MAX);

        if(entry->type != XML_ELEMENT_NODE || name == NULL) {
            dlog(3, "Unable to parse argument entry\n");
            continue;
        }

        if(strcmp(name, "type") == 0) {
            /* String buffer of characters, so type coercion is justified */
            unstripped = (char *)xmlNodeListGetString(doc, entry->xmlChildrenNode, 1);
            if (unstripped == NULL) {
                dlog(3, "Unable to get type information from Copland section\n");
                continue;
            }

            ret = strip_whitespace(unstripped, &type);
            free(unstripped);
            if (ret) {
                dlog(2, "Unable to strip whitespace from Copland type\n");
                continue;
            }

            /* Determine what the argument type is */
            if(strcmp(type, "integer") == 0) {
                tmp->type = INTEGER;
            } else if(strcmp(type, "place") == 0) {
                tmp->type = PLACE;
            } else if(strcmp(type, "string") == 0) {
                tmp->type = STRING;
            } else {
                dlog(1, "Warning: encountered unexpected type %s in argument block\n", type);
                continue;
            }
        } else if(strcmp(name, "values") == 0) {
            if(tmp->type == 0) {
                dlog(1, "Warning: have not processed an argument type yet, have to ignore values right now");
                goto proc_fail;
            }
            dlog(3, "Have not implemented expected values yet, no types need it yet");
        } else {
            dlog(1, "Warning: encountered unexpected element %s in argument block\n", name);
            continue;
        }
    }

    if(tmp->type == 0) {
        dlog(0, "Did not parse a type from the arg entry\n");
        goto proc_fail;
    }

    *arg = tmp;
    return 0;

proc_fail:
    free(tmp->name);
name_err:
name_alloc_err:
    free(tmp);
tmp_alloc_err:
    return -1;
}

/**
 * Parses the APB XML representing the places relevant to the Copland phrase
 * and places it into a Glist of place_perms structs
 * XML argument block is assumed to be formatted as such:
 *
 *      <place id=...>
 *          <info> ... </info>
 *      </place>
 *      ...
 *
 * (in the full context of the copland XML stanza, this is within the
 * <places> block)
 *
 * All of this information will be written into a file which will be made
 * available in the APB's work directory.
 */
int parse_place_block(xmlDocPtr doc, xmlNode *place_block, GList **info)
{
    char *name;
    xmlNode *place;
    GList *tmp_list = NULL, *store = NULL;
    place_perms *tmp_info;

    if(place_block == NULL || info == NULL) {
        dlog(1, "Given null argument\n");
        return -1;
    }

    for(place = place_block->children; place; place = place->next) {
        name = validate_cstring_ascii(place->name, SIZE_MAX);

        if(place->type != XML_ELEMENT_NODE || name == NULL) {
            dlog(4, "Warning: unable to process child place block\n");
            continue;
        }

        if(strcmp(name, "place")) {
            dlog(4, "Warning: non place element found in argument list\n");
            continue;
        }

        if(parse_place_entry(doc, place, &tmp_info) < 0) {
            dlog(1, "Unable to process argument entry\n");
            continue;
        }

        store = g_list_append(tmp_list, tmp_info);
        if (store == NULL) {
            dlog(0, "Unable to add elements to the place info list\n");
            goto err;
        }

        tmp_list = store;
    }

    *info = tmp_list;
    return 0;

err:
    return -1;
}

/*
 * Parses the APB XML representing Copland arguments and places it into a
 * list of phrase_arg structs
 */
int parse_arg_block(xmlDocPtr doc, xmlNode *arg_block, phrase_arg ***args)
{
    int i = 0;
    char *name;
    xmlNode *arg;
    phrase_arg **tmp = NULL, **tmp2 = NULL;

    if(arg_block == NULL) {
        dlog(1, "Given null argument\n");
        return -1;
    }

    for(arg = arg_block->children; arg; arg = arg->next) {
        name = validate_cstring_ascii(arg->name, SIZE_MAX);

        if(arg->type != XML_ELEMENT_NODE || name == NULL) {
            dlog(4, "Warning: unable to process child argument block");
            continue;
        }

        if(strcmp(name, "arg")) {
            dlog(4, "Warning: non argument element found in argument list");
            continue;
        }

        /* type coercion is justified because i is a counter that will always be > 0 */
        tmp2 = realloc(tmp, (size_t)(i + 1) * sizeof(phrase_arg *));
        if (tmp2 == NULL) {
            dlog(0, "Unable to allocate memory to hold parsed copland arguments");
            goto err;
        } else {
            tmp = tmp2;
        }

        if(parse_arg_entry(doc, arg, &tmp[i]) < 0) {
            dlog(1, "Unable to process argument entry\n");
            continue;
        }

        i++;
    }

    *args = tmp;
    return i;

err:
    return -1;
}

/*
 * Given a Copland entry in an APB's XML, adds the information
 * regarding the represented copland phrase to the apb.
 */
void parse_copland(xmlDocPtr doc, struct apb *apb, xmlNode *copl_node, GList *meas_specs)
{
    int ret;
    uuid_t uuid;
    xmlNode *copl_pair_ele = NULL;
    char *name = NULL, *tmp = NULL, *stripped = NULL;
    struct phrase_meas_spec_pair *pair = NULL;
    mspec_info *ms = NULL;
    phrase_arg **args = NULL;

    apb->valid = true;

    pair = malloc(sizeof(struct phrase_meas_spec_pair));
    if(pair == NULL) {
        dlog(0, "Warning: unable to allocate memory in parse_copland for pair object\n");
        goto error;
    }
    memset(pair, 0, sizeof(struct phrase_meas_spec_pair));

    pair->copl = malloc(sizeof(copland_phrase));
    if(pair->copl == NULL) {
        dlog(0, "Unable to allocate memory in parse_copland for phrase\n");
        goto error;
    }
    memset(pair->copl, 0, sizeof(copland_phrase));

    uuid_clear(uuid);

    for (copl_pair_ele = copl_node->children; copl_pair_ele;
            copl_pair_ele = copl_pair_ele->next) {

        name = validate_cstring_ascii(copl_pair_ele->name, SIZE_MAX);
        if (copl_pair_ele->type != XML_ELEMENT_NODE || name == NULL) {
            continue;
        }

        if (strcmp(name, "phrase") == 0) {
            if (pair->copl->phrase != NULL) {
                dlog(2, "Warning: multiple Copland phrases provided for the"
                     "same Copland block in %s\n", apb->name);
                continue;
            }


            /* Since the string is just treated as a buffer, signedness is not an issue */
            tmp = (char *)xmlGetPropASCII(copl_pair_ele, "copland");
            if (tmp == NULL) {
                dlog(1, "Warning: unable to read copland term from Copland block\n");
                apb->valid = false;
                goto error;
            }

            ret = strip_whitespace(tmp, &stripped);
            free(tmp);
            if (ret) {
                dlog(2, "Cannot strip whitespace from Copland phrase\n");
                continue;
            }

            pair->copl->phrase = stripped;
        } else if (strcmp(name, "spec") == 0) {
            if (pair->spec_uuid[0] != 0) {
                dlog(2, "Warning: multiple measurement specs defined for the same "
                     "Copland block in %s\n", apb->name);
                continue;
            }

            tmp = xmlGetPropASCII(copl_pair_ele, "uuid");
            if (!tmp) {
                dlog(3, "Err: Spec entry without UUID, skipping\n");
                continue;
            }

            ret = strip_whitespace(tmp, &stripped);
            free(tmp);
            if (ret) {
                dlog(2, "Unable to strip whitespace from UUID string\n");
                continue;
            }

            ret = uuid_parse(stripped, uuid);
            free(stripped);
            if (ret) {
                dlog(0, "Err: Invalid UUID in entry, skipping\n");
                continue;
            }

            ms = find_measurement_specification_uuid(meas_specs, uuid);
            if (!ms) {
                dlog(1, "Cannot find spec in apb %s with the given uuid\n", apb->name);
                uuid_clear(uuid);
                apb->valid = false;
                continue;
            }

            uuid_copy(pair->spec_uuid, uuid);
        } else if(strcmp(name, "arguments") == 0) {
            ret = parse_arg_block(doc, copl_pair_ele, &args);
            if(ret < 0) {
                dlog(0, "Unable to parse the argument section specified in the APB XML\n");
                apb->valid = false;
                goto error;
            } else if(ret == 0) {
                dlog(3, "No arguments found for the phrase\n");
            } else {
                pair->copl->num_args = ret;
                pair->copl->args = args;
            }
        } else if(strcmp(name, "places") == 0) {
            ret = parse_place_block(doc, copl_pair_ele, &apb->place_permissions);
            if (ret < 0) {
                dlog(0, "Unable to parse the places section specified in the APB XML\n");
                apb->valid = false;
                goto error;
            }
        } else {
            dlog(1, "Warning: malformed APB Copland entry found for APB %s\n",
                 apb->name);
            goto error;
        }
    }

    if(pair->copl->phrase == 0) {
        dlog(1, "Warning: Did not find all required Copland fields required for parsing"
             " in APB %s\n", apb->name);
        apb->valid = false;
        goto error;
    } else {
        pair->copl->role = BASE;
        apb->phrase_specs = g_list_append(apb->phrase_specs, pair);
    }

    return;

error:
    if(pair) {
        free_copland_phrase(pair->copl);

        if (pair->spec_uuid) {
            uuid_clear(pair->spec_uuid);
        }

        free(pair);
    }
}

/*
 * Finds APB from list of available APBs that handles the
 * specified Copland phrase.
 */
struct apb *find_apb_copl(GList *apbs, char *phrase, struct phrase_meas_spec_pair **pair)
{
    GList *l;
    struct phrase_meas_spec_pair *copl;
    struct apb *p;

    for (l = apbs; l && l->data; l = g_list_next(l)) {
        p = (struct apb *)l->data;

        /* If a valid template can be found, then this APB can handle the phrase */
        if(!find_copland_template(phrase, p->phrase_specs, &copl)) {
            if(pair != NULL) {
                *pair = copl;
            }
            return p;
        }
    }

    return NULL;
}

/*
 * Finds an APB from a list of available APB templates that handles
 * the specified Copland phrase. These templates are parsed from
 * APBs when an AM is being instantiated and do not hold
 * concrete values for each argument, so this search is
 * based upon the phrase and number of arguments.
 *
 * Returns an APB on success or NULL on failure. @apbs is
 * a list of available APBs for use by an AM. @phrase is
 * a Copland phrase used by some APB in APBs. @pair is an optional
 * argument which holds the pair of the copland phrase and measurement
 * spec which corresponds to @copl.
 */
struct apb *find_apb_copl_phrase_by_template(GList *apbs, copland_phrase *copl, struct phrase_meas_spec_pair **pair)
{
    GList *l, *m;
    struct phrase_meas_spec_pair *phr_pair;
    struct apb *p;

    for(l = apbs; l && l->data; l = g_list_next(l)) {
        p = (struct apb *)l->data;

        for(m = p->phrase_specs; m && m->data; m = g_list_next(m)) {
            phr_pair = (struct phrase_meas_spec_pair *)m->data;

            if(strcmp(copl->phrase, phr_pair->copl->phrase) == 0
                    && copl->num_args == phr_pair->copl->num_args) {
                if(pair != NULL) {
                    *pair = phr_pair;
                }

                return p;
            }
        }
    }

    return NULL;
}

#define MAX_STR_LEN_UINT32 10

int place_perm_to_str(place_perm_t perm, char **str)
{
    int ret;
    char *tmp;

    if (str == NULL) {
        return -1;
    }

    tmp = calloc(MAX_STR_LEN_UINT32 + 1, 1);
    if (tmp == NULL) {
        return -1;
    }

    ret = snprintf(tmp, MAX_STR_LEN_UINT32 + 1,
                   "%"PRIu32"", perm);
    if (ret < 0) {
        dlog(1,
             "Unable to convert place perm %"PRIu32" to str\n", perm);
        return -1;
    }

    *str = tmp;
    return ret;
}

int str_to_place_perm(const char *str, place_perm_t *perm)
{
    unsigned long tmp;
    char *ptr;

    if (str == NULL || perm == NULL) {
        return -1;
    }

    errno = 0;
    tmp = strtoul(str, &ptr, 10);
    if (errno) {
        dlog(1, "Unable to convert %s to place perm: error %s\n",
             str, strerror(errno));
        return -1;
    }

    *perm = tmp;
    return 0;
}

/**
 * This function checks to see if the Copland phrase has arguments pertaining to
 * Copland places. This could be used to check if calls to query_place_information
 * are required. Returns 1 if place arguments are present and 0 if not.
 *
 * As a warning, although this function will operate correctly on a BASE copland_phrase,
 * a BASE Copland phrase will NOT have the place IDs themselves, so you may want to make
 * sure that the given copland_phrase is an ACTUAL one.
 */
int has_place_args(const copland_phrase *phrase)
{
    int i;

    dlog(4, "Checking for place args in phrase %s\n",
         phrase->phrase);
    for (i = 0; i < phrase->num_args; i++) {
        if (phrase->args[i]->type == PLACE) {
            dlog(4, "Found place arg at index %d\n", i);
            return 1;
        }
    }

    return 0;
}


/**
 * This function parses the CSV line for a column and then appends that information
 * into the out buffer. How it is used in query_place_info_csv is to iterative
 * extend the CSV line which is going to be written out
 *
 * Returns the new size of out if a value was added to the out line,
 * or 0 if an error occured
 */
#define NULL_CONT "0"
static size_t handle_csv_perm_db_line(const char *read_line, size_t len,
                                      place_perm_t perms, int col_indx,
                                      char **out)
{
    int ret;
    size_t ele_len;
    char *tmp;
    char *ele;

    if (read_line == NULL || out == NULL) {
        dlog(1, "Given null return parameter\n");
        return 0;
    }

    if (col_indx < DB_INDX_TO_COL_ADJ) {
        dlog(1, "Index %d less than the adjustment val %d\n",
             col_indx, DB_INDX_TO_COL_ADJ);
        return 0;
    }

    if (perms & DB_INDX_TO_COL(col_indx)) {
        ret = get_col_from_csv_line(read_line,
                                    col_indx,
                                    COPLAND_CSV_LINE_MAX_LEN - len,
                                    &ele);
        if (ret < 0) {
            return 0;
        } else if (ret > 0) {
            dlog(1, "Unable to find ADDR information in CSV file\n");
            return 0;
        }
    } else {
        //Place null content to keep columns
        ele = NULL_CONT;
    }

    ele_len = strlen(ele);
    if (len + ele_len + 2 <= len ||
    len + ele_len + 2 >= COPLAND_CSV_LINE_MAX_LEN) {
        dlog(1, "CSV line would be too long to write out\n");
        ret = -1;
        return 0;
    }
    tmp = realloc(*out, len + ele_len + 2);
    if (tmp == NULL) {
        dlog(0, "Unable to allocate buffer for CSV line\n");
        return 0;
    }

    tmp[len - 1] = ',';
    strcpy(tmp + len, ele);
    tmp[len + ele_len] = '\n';
    tmp[len + ele_len + 1] = '\0';

    len = len + ele_len + 1;

    *out = tmp;
    return len;
}

/**
 * Get place information from the registration CSV file.
 * Returns 0 on success, 1 if the function succeeds but
 * no information is retrieved, 2 if the place is not found,
 * and -1 otherwise.
 *
 * Ultimately, we want multiple of these functions which
 * can be selected during compile time. For now, this is
 * the only one
 */
static int query_place_info_csv(const struct apb *apb,
                                const char *filename,
                                place_perm_t perms,
                                const char *id,
                                char **out_buf)
{
    int ret;
    short parse_flag = 0;
    char *tmp = NULL;
    size_t len;
    size_t tmp_len;
    size_t perm_len;
    char *read_line;
    char *perm;
    char *ele;
    FILE *fp;

    if (apb == NULL || id == NULL || out_buf == NULL) {
        dlog(1, "Given null argument(s) in one parameter that must be dereferenced\n");
        return -1;
    }

    len = strlen(id);

    if(len >= COPLAND_CSV_LINE_MAX_LEN) {
        dlog(1, "Given ID is longer than the maximum allowed line length\n");
        return -1;
    }

    if (perms == 0) {
        dlog(3, "No permissions to access any information on place %s\n", id);
        return 1;
    }

    ret = place_perm_to_str(perms, &perm);
    if (ret < 0) {
        return -1;
    }

    perm_len = strlen(perm);

    if(len + perm_len >= COPLAND_CSV_LINE_MAX_LEN) {
        dlog(1,
             "ID and perms longer than allowed line length\n");
        return -1;
    }

    // Initial entry will be <id>,<perms>\n\0
    tmp = calloc(len + perm_len + 3, 1);
    if (tmp == NULL) {
        dlog(0,
             "Unable to allocate buffer to hold result line\n");
        return -1;
    }

    memcpy(tmp, id, len);
    tmp[len] = ',';
    memcpy(tmp + len + 1, perm, perm_len);
    tmp[len + 1 + perm_len] = '\n';
    /*
     * len in this function is a bit tricky, but in general it will not count
     * \n, mostly because len is used for reallocations and the \n is more or
     * less just moved farther into the string as re-allocations go. Null byte
     * isn't included, but for string length that's normal
     */
    len += (perm_len + 2);
    free(perm);

    ret = read_line_csv(filename, id,
                        COPLAND_DB_PLACE_ID_INDX,
                        COPLAND_CSV_LINE_MAX_LEN, &read_line);

    if (ret == 1) {
        dlog(1, "Unable to find place in the CSV file\n");
        return 2;
    } else if (ret < 0) {
        return ret;
    }

    tmp_len = handle_csv_perm_db_line(read_line, len, perms,
                                      COPLAND_DB_PLACE_ADDR_INDX,
                                      &tmp);
    if (tmp_len == 0) {
        ret = -1;
        goto err;
    } else if (tmp_len > len + strlen(NULL_CONT) + 1) {
        parse_flag = 1;
    }

    len = tmp_len;

    tmp_len = handle_csv_perm_db_line(read_line, len, perms,
                                      COPLAND_DB_PLACE_PORT_INDX,
                                      &tmp);
    if (tmp_len == 0) {
        ret = -1;
        goto err;
    } else if (tmp_len > len + strlen(NULL_CONT) + 1) {
        parse_flag = 1;
    }

    len = tmp_len;

    tmp_len = handle_csv_perm_db_line(read_line, len, perms,
                                      COPLAND_DB_PLACE_KERN_INDX,
                                      &tmp);
    if (tmp_len == 0) {
        ret = -1;
        goto err;
    } else if (tmp_len > len + strlen(NULL_CONT) + 1) {
        parse_flag = 1;
    }

    len = tmp_len;

    tmp_len = handle_csv_perm_db_line(read_line, len, perms,
                                      COPLAND_DB_PLACE_DOM_INDX,
                                      &tmp);
    if (tmp_len == 0) {
        ret = -1;
        goto err;
    } else if (tmp_len > len + strlen(NULL_CONT) + 1) {
        parse_flag = 1;
    }

    len = tmp_len;

    if (parse_flag == 0) {
        ret = 1;
        goto err;
    } else {
        *out_buf = tmp;
        return 0;
    }

err:
    free(tmp);
    return ret;
}

static int get_place_file_name(const struct scenario *scen, char **file_name)
{
    size_t workdir_len;
    size_t perms_file_len;
    char *tmp;

    if (scen == NULL || scen->workdir == NULL || file_name == NULL) {
        dlog(1, "Given null parameters\n");
        return -1;
    }

    workdir_len = strlen(scen->workdir);
    perms_file_len = strlen(COPLAND_PLACE_PERMS_FILE);

    tmp = calloc(workdir_len + perms_file_len + 1, 1);
    if (tmp == NULL) {
        dlog(0, "Unable to allocate memory for workdir filename\n");
        return -1;
    }

    memcpy(tmp, scen->workdir, workdir_len);
    memcpy(tmp + workdir_len,
           COPLAND_PLACE_PERMS_FILE,
           perms_file_len);

    *file_name = tmp;

    return 0;
}

/**
 * When applicable, query for the place information using the compiled in backend.
 * Only the information which we have been given permission in the configuration file
 * to acquire. If a domain is not given a Copland place information, no information will
 * be given pertaining that domain. If place information entry appears with no
 * corresponding domain argument, it will just be ignored. Returns 0 on success
 * and -1 otherwise.
 */
int query_place_information(const struct apb *apb,
                            const struct scenario *scen,
                            const copland_phrase *phrase)
{
    int i;
    int ret = 0;
    ssize_t written;
    char *place_label = NULL;
    char *out_buf = NULL;
    char *file_name = NULL;
    phrase_arg *arg = NULL;
    place_perms *place = NULL;
    GList *place_perm_list = apb->place_permissions;
    GList *perm = NULL;
    struct phrase_meas_spec_pair *pair;

    if (apb == NULL || scen == NULL || phrase == NULL) {
        dlog(1, "Given NULL pointer parameter\n");
        return -1;
    }

    if (place_perm_list == NULL) {
        dlog(4, "No place information permissions given, bypassing the domain argument search\n");
        return 0;
    }

    if (scen->place_file == NULL) {
        dlog(4, "No place filename has been given, bypassing the place information query\n");
        return 0;
    }

    ret = get_place_file_name(scen, &file_name);
    if (ret < 0) {
        dlog(0, "Failed to get place file name\n");
        return ret;
    }

    for(i = 0; i < phrase->num_args; i++) {
        arg = phrase->args[i];

        if(arg->type == PLACE) {
            place_label = arg->name;
            perm = place_perm_list;

            while (perm != NULL) {
                place = (place_perms *)perm->data;
                /**
                         * Need to match permission constraints to
                         * the domain we need to query for information
                         * regarding
                         */
                if (strcmp(place->id, place_label) == 0) {
                    ret = query_place_info_csv(apb,
                                               scen->place_file,
                                               place->perms,
                                               (char *)arg->data,
                                               &out_buf);

                    if(ret != 0) {
                        dlog(1, "Unable to get data for place %s\n", (char *)arg->data);
                        break;
                    } else {
                        dlog(4, "Writing out data %s\n", out_buf);
                        written = append_buffer_to_file(file_name,
                                                        out_buf,
                                                        strlen(out_buf));
                        if (written != strlen(out_buf)) {
                            free(out_buf);
                            ret = -1;
                            dlog(0, "Unable to append place information to CSV file\n");
                            goto end;
                        }

                        free(out_buf);
                    }
                }

                perm = g_list_next(perm);
            }
        }
    }

end:
    free(file_name);
    return ret;
}

/**
 * In APBs that use information pertaining to places, this function can
 * be used to retrieve that information on a per place basis.
 *
 * Returns 0 on success and a -1 otherwise.
 */
int get_place_information(const struct scenario *scen,
                          const char *id, place_info **info)
{
    int ret;
    place_perm_t perms;
    char *file_name;
    char *str;
    char *csv_line;
    place_info *tmp;

    if (scen == NULL || id == NULL || info == NULL ||
            scen->workdir == NULL) {
        dlog(1, "Given null argument\n");
        return -1;
    }

    ret = get_place_file_name(scen, &file_name);
    if (ret < 0) {
        return ret;
    }

    tmp = calloc(sizeof(place_info), 1);
    if (tmp == NULL) {
        dlog(0, "Unable to allocate memory for place info of %s\n", id);
        free(file_name);
        return -1;
    }

    ret = read_line_csv(file_name, id, COPLAND_WORK_PLACE_ID_INDX,
                        COPLAND_CSV_LINE_MAX_LEN, &csv_line);
    free(file_name);
    if (ret != 0) {
        dlog(1, "Unable to read place line from CSV for place : %s\n", id);
        free(tmp);
        return -1;
    }

    ret = get_col_from_csv_line(csv_line,
                                COPLAND_WORK_PLACE_PERMS_INDX,
                                COPLAND_CSV_LINE_MAX_LEN,
                                &str);
    if (ret < 0) {
        dlog(1, "Unable to get place permission from line: %s\n",
             csv_line);
        goto err;
    }

    ret = str_to_place_perm(str, &perms);
    free(str);
    if (ret < 0) {
        dlog(1, "Unable to parse permissions in CSV str %s\n",
             csv_line);
        goto err;
    }

    if (perms & COPLAND_PLACE_ADDR_PERM) {
        ret = get_col_from_csv_line(csv_line,
                                    COPLAND_WORK_PLACE_ADDR_INDX,
                                    COPLAND_CSV_LINE_MAX_LEN,
                                    &str);
        if (ret < 0) {
            dlog(1, "Unable to get address in CSV line: %s\n",
                 csv_line);
            goto err;
        }

        tmp->addr = str;
    }

    if (perms & COPLAND_PLACE_PORT_PERM) {
        ret = get_col_from_csv_line(csv_line,
                                    COPLAND_WORK_PLACE_PORT_INDX,
                                    COPLAND_CSV_LINE_MAX_LEN,
                                    &str);
        if (ret < 0) {
            dlog(1, "Unable to get port in CSV line: %s\n",
                 csv_line);
            goto err;
        }

        tmp->port = str;
    }

    if (perms & COPLAND_PLACE_KERN_PERM) {
        ret = get_col_from_csv_line(csv_line,
                                    COPLAND_WORK_PLACE_KERN_INDX,
                                    COPLAND_CSV_LINE_MAX_LEN,
                                    &str);
        if (ret < 0) {
            dlog(1, "Unable to get kernel in CSV line: %s\n",
                 csv_line);
            goto err;
        }

        tmp->kern_vers = str;
    }

    if (perms & COPLAND_PLACE_DOM_PERM) {
        ret = get_col_from_csv_line(csv_line,
                                    COPLAND_WORK_PLACE_DOM_INDX,
                                    COPLAND_CSV_LINE_MAX_LEN,
                                    &str);
        if (ret < 0) {
            dlog(1, "Unable to get kernel in CSV line: %s\n",
                 csv_line);
            goto err;
        }

        tmp->domain = str;
    }

    free(csv_line);
    *info = tmp;
    return 0;

err:
    free(csv_line);
    free(tmp);
    return -1;
}

/**
 * Frees place information structure memory
 */
void free_place_information(place_info *info)
{
    free(info->addr);
    free(info->port);
    free(info->kern_vers);
    free(info->domain);
    free(info);
}

/* Local Variables:  */
/* mode: c           */
/* c-basic-offset: 4 */
/* End:              */
