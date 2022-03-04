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

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include <util/util.h>
#include <common/asp-errno.h>

#define ASP_NAME "dummy"

#include <asp/asp-api.h>

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    asp_loginfo("Initialized DUMMY plugin\n");
    return ASP_APB_SUCCESS;
}

int asp_exit(int status UNUSED)
{
    asp_loginfo("Exiting DUMMY plugin\n");
    return ASP_APB_SUCCESS;
}

/*
 * return a sha256 hash of a file in the node
 */
int asp_measure(int argc, char *argv[])
{
    asp_loginfo("asp_measure called!\n");
    if (argc != 1) {
        asp_loginfo("Usage <%s> (got argc = %d)\n", argv[0], argc);
        return -EINVAL;
    }
    asp_loginfo("argv[0] = %s\n", argv[0]);
    return ASP_APB_SUCCESS;
}
