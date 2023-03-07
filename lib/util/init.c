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
#include <config.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/conf.h>

#include <util.h>

/*
 * Default values for verbosity settings. The environment variables have
 * the highest priority in determining these values, followed by the 
 * arguments passed into calls to libmaat_init().
 */
int __attribute__((weak)) __libmaat_debug_level = 1;
int __attribute__((weak)) __libmaat_syslog = 1;

/*
 * Generic XML and SSL init and exit routines.
 */
void libmaat_xml_init(void)
{
    LIBXML_TEST_VERSION;
    xmlKeepBlanksDefault(0);
}

void libmaat_xml_exit(void)
{
    xmlCleanupParser();
    xmlMemoryDump();
}

void libmaat_ssl_init(void)
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
}

void libmaat_ssl_exit(void)
{
    ERR_free_strings();

    ENGINE_cleanup();
    EVP_cleanup();

    CONF_modules_finish();
    CONF_modules_free();
    CONF_modules_unload(1);

    CRYPTO_cleanup_all_ex_data();
}

/*
 * LIBMAAT_LOG_SYSLOG is a flag that if set, will convert all dlog calls to syslog calls.
 * By default, this is not set, in which case dlog calls use fprintf() to print the messages to the terminal. 
 * LIBMAAT_DEBUG_LEVEL is the environment variable that sets the level of verbosity. The dlog
 * level must be less than or equal to the LIBMAAT_DEBUG_LEVEL in order to be printed to the terminal.
 */
void libmaat_init(int _syslog, int loglevel)
{
    char *level;
    __libmaat_debug_level = loglevel;
    __libmaat_syslog = _syslog;

    level = getenv("LIBMAAT_DEBUG_LEVEL");
    if (level) {
        unsigned long val;

        errno = 0;
        val = strtoul(level, 0, 10);
        if (errno != 0 || val > INT_MAX ) {
            dperror("Invalid setting for LIBMAAT_DEBUG_LEVEL");
        } else {
            __libmaat_debug_level = (int)val;
        }
    }

    char *syslog = getenv("LIBMAAT_LOG_SYSLOG");
    if (syslog) {
        if(strcasecmp(syslog, "no") == 0 ||
                strcasecmp(syslog, "false") == 0 ||
                strcasecmp(syslog, "0") == 0) {
            __libmaat_syslog = 0;
        } else {
            __libmaat_syslog = 1;
        }
    }

    libmaat_xml_init();
    libmaat_ssl_init();

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void libmaat_exit(void)
{
    libmaat_xml_exit();
    libmaat_ssl_exit();
}
