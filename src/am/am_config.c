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

#include "am_config.h"
#include <util/xml_util.h>
#include <errno.h>
#include <string.h>
#include <util/util.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <arpa/inet.h>

int am_config_add_inet_iface(char *addr, uint16_t port, int skip_negotiation,
                             am_config *cfg)
{
    struct sockaddr_in serv;
    serv.sin_family = AF_INET;
    if(inet_pton(serv.sin_family, addr, &(serv.sin_addr)) != 1) {
        dlog(1, "Error: invalid inet interface IP address "
             "\"%s\"\n", addr);
        return -1;
    }

    am_iface_config *iface = malloc(sizeof(am_iface_config));

    if(iface == NULL) {
        dlog(0, "Failed to allocate listener configuration\n");
        goto error;
    }

    iface->type			= INET;
    iface->port			= (uint16_t)port;
    iface->address		= strdup(addr);
    iface->skip_negotiation	= skip_negotiation;

    if(iface->address == NULL) {
        dlog(0, "Failed to set listener address to %s\n", addr);
        goto error;
    }

    cfg->interfaces = g_list_append(cfg->interfaces, iface);
    return 0;

error:
    free_am_iface_config(iface);
    return -1;
}

int am_config_add_unix_iface(char *path, int skip_negotiation, am_config *cfg)
{
    am_iface_config *iface = malloc(sizeof(am_iface_config));

    if(iface == NULL) {
        dlog(0, "Failed to allocate listener configuration\n");
        goto error;
    }

    iface->type			= UNIX;
    iface->port			= 0;
    iface->address		= strdup(path);
    iface->skip_negotiation	= skip_negotiation;

    if(iface->address == NULL) {
        dlog(0, "Failed to set UNIX socket path to %s\n", path);
        goto error;
    }

    cfg->interfaces = g_list_append(cfg->interfaces, iface);
    return 0;

error:
    free_am_iface_config(iface);
    return -1;
}

int load_inet_iface_config(unsigned int xml_version UNUSED, xmlNode *iface, am_config *cfg)
{
    int skip_neg                = 0;
    char *skipstr               = NULL;
    char *port_str		= NULL;
    unsigned long port_ul	= ULONG_MAX;
    char *endptr                = NULL;
    char *addr			= NULL;
    port_str = xmlGetPropASCII(iface, "port");
    if(port_str == NULL) {
        dlog(1, "Warning: ignoring invalid inet interface with "
             "missing port number\n");
        return -1;
    }
    errno = 0;
    port_ul = strtoul(port_str, &endptr, 10);
    if(port_str == endptr || errno != 0 || *endptr != '\0' || port_ul > UINT16_MAX) {
        dlog(1, "Warning: ignoring invalid inet interface "
             "with bad port \"%s\"\n", port_str);
        xmlFree(port_str);
        return -1;
    }

    xmlFree(port_str);

    addr = xmlGetPropASCII(iface, "address");

    if(addr == NULL) {
        dlog(1, "Warning: ignoring invalid inet interface "
             "with missing address\n");
        return -1;
    }

    skipstr = xmlGetPropASCII(iface, "skip-negotiation");
    if(skipstr != NULL && (strcasecmp(skipstr, "true") == 0 ||
                           strcasecmp(skipstr, "1") == 0)) {
        skip_neg = 1;
    }

    int rc = am_config_add_inet_iface(addr, (uint16_t)port_ul, skip_neg, cfg);
    xmlFree(addr);
    return rc;
}

int load_unix_iface_config(unsigned int xml_version UNUSED, xmlNode *iface, am_config *cfg)
{
    char *skipstr = NULL;
    char *addr    = xmlGetPropASCII(iface, "path");
    if(addr == NULL) {
        dlog(2, "Warning: ignoring invalid unix interface "
             "with missing path\n");
        return -1;
    }

    skipstr = xmlGetPropASCII(iface, "skip-negotiation");
    if(skipstr != NULL && (strcasecmp(skipstr, "true") == 0 ||
                           strcasecmp(skipstr, "1") == 0)) {
        am_config_add_unix_iface(addr, 1, cfg);
    } else {
        am_config_add_unix_iface(addr, 0, cfg);
    }
    xmlFree(addr);
    xmlFree(skipstr);
    return 0;
}

void load_iface_configs(unsigned int xml_version, xmlNode *interfaces, am_config *cfg)
{
    if(cfg->interfaces != NULL) {
        dlog(2, "Warning: interfaces in configuration file were overridden\n");
        return;
    }
    xmlNode *iface;
    for(iface = interfaces->children; iface != NULL; iface = iface->next) {
        char *iface_type	= NULL;
        char *iface_name        = validate_cstring_ascii(iface->name, SIZE_MAX);
        if(iface_name == NULL || strcasecmp(iface_name, "interface") != 0) {
            continue;
        }

        iface_type = xmlGetPropASCII(iface, "type");
        if(iface_type == NULL) {
            dlog(2, "Warning: interface does not specify a type. Skipping\n.");
            free(iface_type);
            continue;
        }

        if(strcasecmp(iface_type, "inet") == 0) {
            load_inet_iface_config(xml_version, iface, cfg);
        } else if(strcasecmp(iface_type, "unix") == 0) {
            load_unix_iface_config(xml_version, iface, cfg);
        } else {
            dlog(2, "Warning: ignoring invalid interface of type \"%s\"\n",
                 iface_type);
        }
        free(iface_type);
    }
}

int load_credentials_config(unsigned int xml_version UNUSED, xmlNode *credentials, am_config *cfg)
{
    xmlNode *node = NULL;
    char *contents  = NULL;
    int set_priv_key = 0;
    int set_cert = 0;
    int set_cacert = 0;
    int set_tpm = 0;
    for(node = credentials->children; node != NULL; node = node->next) {
        char *node_name = validate_cstring_ascii(node->name, SIZE_MAX);
        if(node-> type != XML_ELEMENT_NODE || node_name == NULL) {
            continue;
        }

        contents = xmlNodeGetContentASCII(node);
        if(contents && *contents == '\0') {
            dlog(1, "Error: \"%s\" node had no content\n", node_name);
            goto cleanup;
        }

        if(strcasecmp(node_name, "private-key") == 0) {
            if(cfg->privkey_file == NULL) {
                cfg->privkey_file = contents;
                cfg->privkey_pass = xmlGetPropASCII(node, "password");
                set_priv_key = 1;
            } else if(set_priv_key) {
                dlog(1, "Error: too many \"%s\" nodes\n", node_name);
                goto cleanup;
            } else {
                dlog(2, "Warning: %s in configuration file was overridden\n", node_name);
                set_priv_key = 1;
            }
        } else if(strcasecmp(node_name, "certificate") == 0) {
            if(cfg->cert_file == NULL) {
                cfg->cert_file = contents;
                set_cert = 1;
            } else if(set_cert) {
                dlog(1, "Error: too many \"%s\" nodes\n", node_name);
                goto cleanup;
            } else {
                dlog(2, "Warning: %s in configuration file was overridden\n", node_name);
                set_cert = 1;
            }
        } else if(strcasecmp(node_name, "ca-certificate") == 0) {
            if(cfg->cacert_file == NULL) {
                cfg->cacert_file = contents;
                set_cacert = 1;
            } else if(set_cacert) {
                dlog(2, "Warning: multiple \"%s\" nodes not yet supported, "
                     "ignoring extras\n", node_name);
                xmlFree(contents);
            } else {
                dlog(2, "Warning: %s in configuration file was overridden\n", node_name);
                set_cacert = 1;
            }
        } else if(strcasecmp(node_name, "tpm-password") == 0) {
            if(cfg->tpm_pass == NULL) {
                cfg->tpm_pass = contents;
                set_tpm = 1;
            } else if (set_tpm) {
                dlog(2, "Warning: multiple \"%s\" nodes not yet supported, "
                     "ignoring extras\n", node_name);
                xmlFree(contents);
            } else {
                dlog(2, "Warning: %s in the configuration file was overridden\n", node_name);
                set_tpm = 1;
            }
        } else {
            dlog(1, "Error: unexpected credential node \"%s\"\n", node_name);
            goto cleanup;
        }
    }
    return 0;

cleanup:
    xmlFree(contents);
    contents = NULL;
    xmlFree(cfg->privkey_file);
    cfg->privkey_file = NULL;
    xmlFree(cfg->privkey_pass);
    cfg->privkey_pass = NULL;
    xmlFree(cfg->cert_file);
    cfg->cert_file = NULL;
    xmlFree(cfg->cacert_file);
    cfg->cacert_file = NULL;
    xmlFree(cfg->tpm_pass);
    cfg->tpm_pass = NULL;
    return -1;
}

void load_metadata_config(unsigned int xml_version UNUSED, xmlNode *metadata, am_config *cfg)
{
    char *type = xmlGetPropASCII(metadata, "type");
    char *dir = xmlGetPropASCII(metadata, "dir");

    if(type == NULL) {
        dlog(2, "Warning: metadata node with missing or invalid type attribute\n");
        xmlFree(dir);
    } else if(strcasecmp(type, "asps") == 0) {
        if(cfg->asp_metadata_dir == NULL) {
            cfg->asp_metadata_dir = dir;
        } else {
            xmlFree(dir);
        }
    } else if(strcasecmp(type, "apbs") == 0) {
        if(cfg->apb_metadata_dir == NULL) {
            cfg->apb_metadata_dir = dir;
        } else {
            xmlFree(dir);
        }
    } else if(strcasecmp(type, "measurement-specifications") == 0) {
        if(cfg->mspec_dir == NULL) {
            cfg->mspec_dir = dir;
        } else {
            xmlFree(dir);
        }
    } else {
        dlog(2, "Warning: unknown metadata type \"%s\"\n", type);
        xmlFree(dir);
    }
    xmlFree(type);
}

int load_selector_config(unsigned int xml_version UNUSED, xmlNode *selector, am_config *config)
{
    /*
     * If the selector source location is already set, just return, don't
     * overwrite. For example, if the selection policy is listed in the am
     * config and passed via command line.
     */
    if(config->selector_source.loc != NULL) {
        dlog(2, "Warning: selector in configuration file was overridden\n");
        return 0;
    }

    int ret = -1;
    xmlNode *node;
    char *contents = NULL;
    for(node = selector->children; node != NULL; node = node->next) {
        char *node_name = validate_cstring_ascii(node->name, SIZE_MAX);
        if(node-> type != XML_ELEMENT_NODE || node_name == NULL) {
            continue;
        }

        if (strcasecmp(node_name, "path") != 0) {
            dlog(2, "Warning: unrecognized selector configuration "
                 "child node \"%s\"\n", node_name);
            continue;
        }

        contents = xmlNodeGetContentASCII(node);
        if(contents && *contents == '\0') {
            xmlFree(contents);
            contents = NULL;
        }
    }
    if (!contents) {
        dlog(2, "Warning: selector configuration was missing path child node "
             "or the node lacked content\n");
        return ret;
    }

    char *type = xmlGetPropASCII(selector, "source");
    if(type == NULL) {
        dlog(2, "Warning: Missing or invalid selector source. (ignoring).\n");
    } else {
        if(strcasecmp(type, "file") == 0) {
            config->selector_source.method = strdup(SELECTOR_COPL);
            config->selector_source.loc = contents;
        } else if(strcasecmp(type, "mongo") == 0) {
            config->selector_source.method = strdup(SELECTOR_MONGO);
            config->selector_source.loc = contents;
        } else {
            dlog(2, "Warning: Invalid selector source \"%s\" (ignoring)\n", type);
            goto cleanup;
        }
        xmlFree(type);

        if(config->selector_source.method == NULL ||
                *config->selector_source.loc == '\0') {
            dlog(0, "Error: Failed to load selector from config file\n");
            goto cleanup;
        } else {
            return 0;
        }
    }
cleanup:
    xmlFree(contents);
    xmlFree(type);
    free(config->selector_source.method);
    config->selector_source.method = NULL;
    config->selector_source.loc = NULL;
    return ret;
}

int attestmgr_load_config(const char *cfg_path, am_config *cfg)
{
    xmlDoc *doc = xmlReadFile(cfg_path, NULL, 0);
    xmlNode *root;
    xmlNode *node;
    char *rootname = NULL;

    if(doc == NULL) {
        goto xml_parse_failed;
    }

    root = xmlDocGetRootElement(doc);
    rootname = validate_cstring_ascii(root->name, SIZE_MAX);
    if(rootname == NULL || strcasecmp(rootname, "am-config") != 0) {
        dlog(1, "Error: invalid configuration file \"%s\". Should be an am-config xml.\n",
             cfg_path);
        goto bad_root_node;
    }

    char *version;
    unsigned int xml_version = 0;
    if ((version = xmlGetPropASCII(root, "version")) != NULL) {
        if(sscanf(version, "%u", &xml_version) != 1) {
            xml_version = 0;
        }
        free(version);
    }

    for(node = root->children; node != NULL; node = node->next) {
        char *node_name = validate_cstring_ascii(node->name, SIZE_MAX);
        if(node->type != XML_ELEMENT_NODE || node_name == NULL) {
            continue;
        }
        if(strcasecmp(node_name, "interfaces") == 0) {
            load_iface_configs(xml_version, node, cfg);
        } else if(strcasecmp(node_name, "selector") == 0) {
            if(load_selector_config(xml_version, node, cfg) != 0) {
                goto bad_selector;
            }
        } else if(strcasecmp(node_name, "credentials") == 0) {
            if (load_credentials_config(xml_version, node, cfg) != 0) {
                goto bad_credentials;
            }
        } else if(strcasecmp(node_name, "metadata") == 0) {
            load_metadata_config(xml_version, node, cfg);
        } else if(strcasecmp(node_name, "work") == 0) {
            if(cfg->workdir == NULL) {
                cfg->workdir = xmlGetPropASCII(node, "dir");
                if(cfg->workdir == NULL) {
                    dlog(2, "Warning: invalid or missing \"dir\" attribute of "
                         "<work> node (ignoring).\n");
                }
            }
        } else if(strcasecmp(node_name, "place") == 0) {
            if(cfg->place_file == NULL) {
                cfg->place_file = xmlGetPropASCII(node, "name");
                if(cfg->place_file == NULL) {
                    dlog(2, "Warning: invalid or missing \"name\" attribute of "
                         "<place> node (ignoring).\n");
                }
            }
        } else if(strcasecmp(node_name, "user") == 0) {
            if(cfg->uid_set == 0) {
                char *username    = xmlNodeGetContentASCII(node);
                if(username == NULL) {
                    dlog(1, "Error: invalid user node in config file\n");
                    goto bad_user_node;
                }

                struct passwd *pw = getpwnam(username);
                if(pw != NULL) {
                    cfg->uid_set = 1;
                    cfg->uid     = pw->pw_uid;
                } else {
                    dlog(1, "Error: unknown user \"%s\" in config file\n", username);
                    xmlFree(username);
                    goto bad_user_node;
                }
                xmlFree(username);
            }
        } else if(strcasecmp(node_name, "group") == 0) {
            if(cfg->gid_set == 0) {
                char *groupname = xmlNodeGetContentASCII(node);
                if(groupname == NULL) {
                    dlog(1, "Error: invalid group node in config file.\n");
                    goto bad_user_node;
                }
                struct group *gr = getgrnam(groupname);
                if(gr != NULL) {
                    cfg->gid_set = 1;
                    cfg->gid     = gr->gr_gid;
                } else {
                    dlog(1, "Error: unknown group \"%s\" in config file\n", groupname);
                    xmlFree(groupname);
                    goto bad_user_node;
                }
                xmlFree(groupname);
            }
        } else if(strcasecmp(node_name, "timeout") == 0) {
            if(cfg->timeout_set == 0) {
                char *timeout_val = xmlGetPropASCII(node, "seconds");
                char *end;
                long timeout_l = 0;
                if(timeout_val == NULL) {
                    dlog(0, "Timeout node must contain \"seconds\" attribute\n");
                    goto bad_timeout;
                }

                errno = 0;
                timeout_l = strtol(timeout_val, &end, 10);
                if((timeout_l < 0) ||
                        (timeout_l == LONG_MAX && errno != 0) ||
                        (*end != '\0') ||
                        (timeout_l > MAX_AM_COMM_TIMEOUT)) {
                    dlog(0, "Invalid value for AM Communications timeout \"%s\""
                         "must be an integer between 0 and %d\n",
                         timeout_val, MAX_AM_COMM_TIMEOUT);
                    free(timeout_val);
                    goto bad_timeout;
                }
                cfg->am_comm_timeout = timeout_l;
                cfg->timeout_set = 1;
                free(timeout_val);
            }
        } else if(strcasecmp(node_name, "execcon_ignore_desired") == 0) {
            dlog(3, "Found EXECCON_IGNORE_DESIRED node in AM configuration\n");
            cfg->execcon_behavior = EXECCON_IGNORE_DESIRED;
        } else if(strcasecmp(node_name, "use_default_categories") == 0) {
            dlog(3, "Found USE_DEFAULT_CATEGORIES node in AM configuration\n");
            cfg->use_unique_categories = EXECCON_USE_DEFAULT_CATEGORIES;
        }
    }

    xmlFreeDoc(doc);
    return 0;

bad_timeout:
bad_user_node:
bad_selector:
bad_credentials:
bad_root_node:
    xmlFreeDoc(doc);
xml_parse_failed:
    return -1;
}

void free_am_config_data(am_config *cfg)
{
    if(!cfg) {
        return;
    }
    g_list_free_full(cfg->interfaces, (GDestroyNotify)free_am_iface_config);

    xmlFree(cfg->selector_source.loc);
    free(cfg->selector_source.method);
    free(cfg->place_file);

    xmlFree(cfg->cacert_file);
    xmlFree(cfg->cert_file);
    xmlFree(cfg->privkey_file);
    xmlFree(cfg->privkey_pass);
    xmlFree(cfg->asp_metadata_dir);
    xmlFree(cfg->apb_metadata_dir);
    xmlFree(cfg->mspec_dir);
    xmlFree(cfg->workdir);
}
