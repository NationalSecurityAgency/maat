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

#include <stdint.h>
#include <errno.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <check.h>
#include <inttypes.h>
#include <pwd.h>
#include <grp.h>

#include <util/util.h>
#include <util/xml_util.h>
#include <am/am_config.h>

int load_inet_iface_config(unsigned int xml_version UNUSED, xmlNode *iface, am_config *cfg);
int load_unix_iface_config(unsigned int xml_version UNUSED, xmlNode *iface, am_config *cfg);
void load_iface_configs(unsigned int xml_version, xmlNode *interfaces, am_config *cfg);
int load_credentials_config(unsigned int xml_version UNUSED, xmlNode *credentials, am_config *cfg);
void load_metadata_config(unsigned int xml_version UNUSED, xmlNode *metadata, am_config *cfg);
int load_selector_config(unsigned int xml_version UNUSED, xmlNode *selector, am_config *config);

START_TEST(test_load_inet_iface_config)
{
    char *iface_cfg_str = "<interface type=\"inet\" address=\"0.0.0.0\" port=\"2342\" />";
    am_config cfg = {0};
    xmlDoc *d = get_doc_from_blob(iface_cfg_str, xmlStrlen(iface_cfg_str));
    ck_assert(d != NULL);
    xmlNode *root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_inet_iface_config(0, root, &cfg), 0);
    ck_assert(cfg.interfaces != NULL);
    ck_assert(cfg.interfaces->data != NULL);
    am_iface_config *iface = cfg.interfaces->data;
    ck_assert(iface->type == INET);
    ck_assert(iface->address != NULL);
    ck_assert_str_eq(iface->address, "0.0.0.0");
    ck_assert_int_eq(iface->port, 2342);
    ck_assert_int_eq(iface->skip_negotiation, 0);
    g_list_free_full(cfg.interfaces, (GDestroyNotify)free_am_iface_config);
    xmlFreeDoc(d);
}
END_TEST

START_TEST(test_load_invalid_inet_iface_config)
{
    // Missing port
    char *iface_cfg_str = "<interface type=\"inet\" address=\"0.0.0.0\" />";
    am_config cfg = {0};
    xmlDoc *d = get_doc_from_blob(iface_cfg_str, xmlStrlen(iface_cfg_str));
    xmlNode *root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_inet_iface_config(0, root, &cfg), -1);
    xmlFreeDoc(d);

    // Empty port
    iface_cfg_str = "<interface type=\"inet\" address=\"0.0.0.0\" port=\"\" />";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(iface_cfg_str, xmlStrlen(iface_cfg_str));
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_inet_iface_config(0, root, &cfg), -1);
    xmlFreeDoc(d);

    // Non-integral port
    iface_cfg_str = "<interface type=\"inet\" address=\"0.0.0.0\" port=\"abc\" />";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(iface_cfg_str, xmlStrlen(iface_cfg_str));
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_inet_iface_config(0, root, &cfg), -1);
    xmlFreeDoc(d);

    // Negative port
    iface_cfg_str = "<interface type=\"inet\" address=\"0.0.0.0\" port=\"-1\" />";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(iface_cfg_str, xmlStrlen(iface_cfg_str));
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_inet_iface_config(0, root, &cfg), -1);
    xmlFreeDoc(d);

    // Overlarge port
    iface_cfg_str = "<interface type=\"inet\" address=\"0.0.0.0\" port=\"65536\" />";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(iface_cfg_str, xmlStrlen(iface_cfg_str));
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_inet_iface_config(0, root, &cfg), -1);
    xmlFreeDoc(d);

    // Missing address
    iface_cfg_str = "<interface type=\"inet\" port=\"2342\" />";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(iface_cfg_str, xmlStrlen(iface_cfg_str));
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_inet_iface_config(0, root, &cfg), -1);
    xmlFreeDoc(d);

    // Invalid address - too large
    iface_cfg_str = "<interface type=\"inet\" address=\"0.0.256.0\" port=\"2342\" />";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(iface_cfg_str, xmlStrlen(iface_cfg_str));
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_inet_iface_config(0, root, &cfg), -1);
    xmlFreeDoc(d);

    // Invalid address - negative
    iface_cfg_str = "<interface type=\"inet\" address=\"0.-1.0.0\" port=\"2342\" />";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(iface_cfg_str, xmlStrlen(iface_cfg_str));
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_inet_iface_config(0, root, &cfg), -1);
    xmlFreeDoc(d);

    // Invalid address - truncated
    iface_cfg_str = "<interface type=\"inet\" address=\"1.2.3\" port=\"2342\" />";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(iface_cfg_str, xmlStrlen(iface_cfg_str));
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_inet_iface_config(0, root, &cfg), -1);
    xmlFreeDoc(d);

    // Invalid address - extra
    iface_cfg_str = "<interface type=\"inet\" address=\"1.2.3.4.5\" port=\"2342\" />";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(iface_cfg_str, xmlStrlen(iface_cfg_str));
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_inet_iface_config(0, root, &cfg), -1);
    xmlFreeDoc(d);

    // Invalid address - hostname
    iface_cfg_str = "<interface type=\"inet\" address=\"localhost\" port=\"2342\" />";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(iface_cfg_str, xmlStrlen(iface_cfg_str));
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_inet_iface_config(0, root, &cfg), -1);
    xmlFreeDoc(d);
}
END_TEST

START_TEST(test_load_unix_iface_config)
{
    char *iface_cfg_str = "<interface type=\"unix\" path=\"/foo/bar/baz\" />";
    am_config cfg = {0};
    xmlDoc *d = get_doc_from_blob(iface_cfg_str, xmlStrlen(iface_cfg_str));
    ck_assert(d != NULL);
    xmlNode *root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_unix_iface_config(0, root, &cfg), 0);
    ck_assert(cfg.interfaces != NULL);
    ck_assert(cfg.interfaces->data != NULL);
    am_iface_config *iface = cfg.interfaces->data;
    ck_assert(iface->type == UNIX);
    ck_assert(iface->address != NULL);
    ck_assert_str_eq(iface->address, "/foo/bar/baz");
    ck_assert_int_eq(iface->skip_negotiation, 0);
    g_list_free_full(cfg.interfaces, (GDestroyNotify)free_am_iface_config);
    xmlFreeDoc(d);

    iface_cfg_str = "<interface type=\"unix\" path=\"/foo/bar/baz\" skip-negotiation=\"true\"/>";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(iface_cfg_str, xmlStrlen(iface_cfg_str));
    ck_assert(d != NULL);
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_unix_iface_config(0, root, &cfg), 0);
    ck_assert(cfg.interfaces != NULL);
    ck_assert(cfg.interfaces->data != NULL);
    iface = cfg.interfaces->data;
    ck_assert(iface->type == UNIX);
    ck_assert(iface->address != NULL);
    ck_assert_str_eq(iface->address, "/foo/bar/baz");
    ck_assert_int_eq(iface->skip_negotiation, 1);
    g_list_free_full(cfg.interfaces, (GDestroyNotify)free_am_iface_config);
    xmlFreeDoc(d);

    iface_cfg_str = "<interface type=\"unix\" path=\"/foo/bar/baz\" skip-negotiation=\"True\"/>";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(iface_cfg_str, xmlStrlen(iface_cfg_str));
    ck_assert(d != NULL);
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_unix_iface_config(0, root, &cfg), 0);
    ck_assert(cfg.interfaces != NULL);
    ck_assert(cfg.interfaces->data != NULL);
    iface = cfg.interfaces->data;
    ck_assert(iface->type == UNIX);
    ck_assert(iface->address != NULL);
    ck_assert_str_eq(iface->address, "/foo/bar/baz");
    ck_assert_int_eq(iface->skip_negotiation, 1);
    g_list_free_full(cfg.interfaces, (GDestroyNotify)free_am_iface_config);
    xmlFreeDoc(d);

    iface_cfg_str = "<interface type=\"unix\" path=\"/foo/bar/baz\" skip-negotiation=\"false\"/>";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(iface_cfg_str, xmlStrlen(iface_cfg_str));
    ck_assert(d != NULL);
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_unix_iface_config(0, root, &cfg), 0);
    ck_assert(cfg.interfaces != NULL);
    ck_assert(cfg.interfaces->data != NULL);
    iface = cfg.interfaces->data;
    ck_assert(iface->type == UNIX);
    ck_assert(iface->address != NULL);
    ck_assert_str_eq(iface->address, "/foo/bar/baz");
    ck_assert_int_eq(iface->skip_negotiation, 0);
    g_list_free_full(cfg.interfaces, (GDestroyNotify)free_am_iface_config);
    xmlFreeDoc(d);
}
END_TEST

START_TEST(test_load_invalid_unix_iface_config)
{
    char *iface_cfg_str = "<interface type=\"unix\" />";
    am_config cfg = {0};
    xmlDoc *d = get_doc_from_blob(iface_cfg_str, xmlStrlen(iface_cfg_str));
    ck_assert(d != NULL);
    xmlNode *root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_unix_iface_config(0, root, &cfg), -1);
    xmlFreeDoc(d);
}
END_TEST

START_TEST(test_load_iface_configs)
{
    char *iface_cfgs_str =
        "<interfaces>"
        "<interface type=\"unix\" path=\"/foo/bar/baz\" />"
        "<interface type=\"inet\" address=\"0.0.0.0\" port=\"2342\" />"
        "<interface type=\"unix\" path=\"/foo/bar/baz\" skip-negotiation=\"True\"/>"
        "</interfaces>";
    am_config cfg = {0};
    xmlDoc *d = get_doc_from_blob(iface_cfgs_str, xmlStrlen(iface_cfgs_str));
    ck_assert(d != NULL);
    xmlNode *root = xmlDocGetRootElement(d);
    load_iface_configs(0, root, &cfg);

    ck_assert(cfg.interfaces != NULL);
    GList *iface_node = cfg.interfaces;
    ck_assert(iface_node->data != NULL);
    am_iface_config *iface = iface_node->data;
    ck_assert(iface->type == UNIX);
    ck_assert(iface->address != NULL);
    ck_assert_str_eq(iface->address, "/foo/bar/baz");
    ck_assert(!iface->skip_negotiation);

    iface_node = iface_node->next;
    ck_assert(iface_node != NULL);
    ck_assert(iface_node->data != NULL);
    iface = iface_node->data;
    ck_assert(iface->type == INET);
    ck_assert(iface->address != NULL);
    ck_assert_str_eq(iface->address, "0.0.0.0");
    ck_assert_int_eq(iface->port, 2342);
    ck_assert(!iface->skip_negotiation);

    iface_node = iface_node->next;
    ck_assert(iface_node != NULL);
    ck_assert(iface_node->data != NULL);
    iface = iface_node->data;
    ck_assert(iface->type == UNIX);
    ck_assert(iface->address != NULL);
    ck_assert_str_eq(iface->address, "/foo/bar/baz");
    ck_assert(iface->skip_negotiation);

    ck_assert(iface_node->next == NULL);
    g_list_free_full(cfg.interfaces, (GDestroyNotify)free_am_iface_config);
    xmlFreeDoc(d);

    // No interfaces
    iface_cfgs_str = "<interfaces/>";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(iface_cfgs_str, xmlStrlen(iface_cfgs_str));
    ck_assert(d != NULL);
    root = xmlDocGetRootElement(d);
    load_iface_configs(0, root, &cfg);
    ck_assert(cfg.interfaces == NULL);
    xmlFreeDoc(d);
}
END_TEST

START_TEST(test_load_invalid_iface_configs)
{
    char *iface_cfgs_str =
        "<interfaces>"
        "<interface type=\"unix\" path=\"/foo/bar/baz\" />"
        "<interface type=\"inet\" address=\"0.0.0.0\" />"
        "<interface type=\"inet\" address=\"0.0.0.0\" port=\"2342\" />"
        "<interface type=\"unix\" />"
        "<interface type=\"X\" />"
        "<interface type=\"unix\" path=\"/foo/bar/baz\" skip-negotiation=\"True\"/>"
        "</interfaces>";
    am_config cfg = {0};
    xmlDoc *d = get_doc_from_blob(iface_cfgs_str, xmlStrlen(iface_cfgs_str));
    ck_assert(d != NULL);
    xmlNode *root = xmlDocGetRootElement(d);
    load_iface_configs(0, root, &cfg);

    GList *iface_node = cfg.interfaces;
    ck_assert(iface_node != NULL);
    ck_assert(iface_node->data != NULL);
    am_iface_config *iface = iface_node->data;
    ck_assert(iface->type == UNIX);
    ck_assert(iface->address != NULL);
    ck_assert_str_eq(iface->address, "/foo/bar/baz");
    ck_assert_int_eq(iface->skip_negotiation, 0);

    iface_node = iface_node->next;
    ck_assert(iface_node != NULL);
    ck_assert(iface_node->data != NULL);
    iface = iface_node->data;
    ck_assert(iface->type == INET);
    ck_assert(iface->address != NULL);
    ck_assert_str_eq(iface->address, "0.0.0.0");
    ck_assert(iface->port == 2342);
    ck_assert_int_eq(iface->skip_negotiation, 0);

    iface_node = iface_node->next;
    ck_assert(iface_node != NULL);
    ck_assert(iface_node->data != NULL);
    iface = iface_node->data;
    ck_assert(iface->type == UNIX);
    ck_assert(iface->address != NULL);
    ck_assert_str_eq(iface->address, "/foo/bar/baz");
    ck_assert_int_eq(iface->skip_negotiation, 1);

    ck_assert(iface_node->next == NULL);
    g_list_free_full(cfg.interfaces, (GDestroyNotify)free_am_iface_config);
    xmlFreeDoc(d);
}
END_TEST

START_TEST(test_load_credentials_config)
{
    char *creds_cfg_str =
        "<credentials>"
        "<private-key password=\"bubblegum\" >/somewhere/pk</private-key>"
        "<certificate>/elsewhere/cert</certificate>"
        "<ca-certificate>/whoknowswhere/ca-cert</ca-certificate>"
        "<tpm-password>cherry</tpm-password>"
        "<akctx>/where/ctx</akctx>"
        "<akpubkey>/whereelse/pubkey</akpubkey>"
        "</credentials>";
    am_config cfg = {0};
    xmlDoc *d = get_doc_from_blob(creds_cfg_str, xmlStrlen(creds_cfg_str));
    ck_assert(d != NULL);
    xmlNode *root = xmlDocGetRootElement(d);
    load_credentials_config(0, root, &cfg);
    ck_assert_str_eq(cfg.privkey_pass, "bubblegum");
    ck_assert_str_eq(cfg.privkey_file, "/somewhere/pk");
    ck_assert_str_eq(cfg.cert_file, "/elsewhere/cert");
    ck_assert_str_eq(cfg.cacert_file, "/whoknowswhere/ca-cert");
    ck_assert_str_eq(cfg.tpmpass, "cherry");
    ck_assert_str_eq(cfg.akctx, "/where/ctx");
    ck_assert_str_eq(cfg.akpubkey, "/whereelse/pubkey");

    xmlFreeDoc(d);
    free_am_config_data(&cfg);

    // No credentials
    creds_cfg_str = "<credentials/>";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(creds_cfg_str, xmlStrlen(creds_cfg_str));
    ck_assert(d != NULL);
    root = xmlDocGetRootElement(d);
    load_credentials_config(0, root, &cfg);
    ck_assert(cfg.privkey_file == NULL);
    ck_assert(cfg.privkey_pass == NULL);
    ck_assert(cfg.cert_file == NULL);
    ck_assert(cfg.cacert_file == NULL);
    ck_assert(cfg.tpmpass == NULL);
    ck_assert(cfg.akctx == NULL);
    ck_assert(cfg.akpubkey == NULL);

    xmlFreeDoc(d);
}
END_TEST

START_TEST(test_load_invalid_credentials_config)
{
    // Unknown node
    char *creds_cfg_str =
        "<credentials>"
        "<unexpectedCredentialNode>someContent</unexpectedCredentialNode>"
        "<private-key password=\"bubblegum\" >/somewhere/pk</private-key>"
        "<certificate>/elsewhere/cert</certificate>"
        "<ca-certificate>/whoknowswhere/ca-cert</ca-certificate>"
        "<tpm-password>cherry</tpm-password>"
        "<akctx>/where/ctx</akctx>"
        "<akpubkey>/whereelse/pubkey</akpubkey>"
        "</credentials>";
    am_config cfg = {0};
    xmlDoc *d = get_doc_from_blob(creds_cfg_str, xmlStrlen(creds_cfg_str));
    ck_assert(d != NULL);
    xmlNode *root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_credentials_config(0, root, &cfg), -1);
    ck_assert(cfg.privkey_pass == NULL);
    ck_assert(cfg.privkey_file == NULL);
    ck_assert(cfg.cert_file == NULL);
    ck_assert(cfg.cacert_file == NULL);
    ck_assert(cfg.tpmpass == NULL);
    ck_assert(cfg.akctx == NULL);
    ck_assert(cfg.akpubkey == NULL);
    xmlFreeDoc(d);

    // Invalid nodes (missing content)
    creds_cfg_str =
        "<credentials>"
        "<private-key/>"
        "<certificate>/elsewhere/cert</certificate>"
        "<ca-certificate>/whoknowswhere/ca-cert</ca-certificate>"
        "<tpm-password>cherry</tpm-password>"
        "<akctx>/where/ctx</akctx>"
        "<akpubkey>/whereelse/pubkey</akpubkey>"
        "</credentials>";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(creds_cfg_str, xmlStrlen(creds_cfg_str));
    ck_assert(d != NULL);
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_credentials_config(0, root, &cfg), -1);
    ck_assert(cfg.privkey_pass == NULL);
    ck_assert(cfg.privkey_file == NULL);
    ck_assert(cfg.cert_file == NULL);
    ck_assert(cfg.cacert_file == NULL);
    ck_assert(cfg.tpmpass == NULL);
    ck_assert(cfg.akctx == NULL);
    ck_assert(cfg.akpubkey == NULL);
    xmlFreeDoc(d);

    creds_cfg_str =
        "<credentials>"
        "<private-key password=\"bubblegum\" >/somewhere/pk</private-key>"
        "<certificate/>"
        "<ca-certificate>/whoknowswhere/ca-cert</ca-certificate>"
        "<tpm-password>cherry</tpm-password>"
        "<akctx>/where/ctx</akctx>"
        "<akpubkey>/whereelse/pubkey</akpubkey>"
        "</credentials>";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(creds_cfg_str, xmlStrlen(creds_cfg_str));
    ck_assert(d != NULL);
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_credentials_config(0, root, &cfg), -1);
    ck_assert(cfg.privkey_pass == NULL);
    ck_assert(cfg.privkey_file == NULL);
    ck_assert(cfg.cert_file == NULL);
    ck_assert(cfg.cacert_file == NULL);
    ck_assert(cfg.tpmpass == NULL);
    ck_assert(cfg.akctx == NULL);
    ck_assert(cfg.akpubkey == NULL);
    xmlFreeDoc(d);

    creds_cfg_str =
        "<credentials>"
        "<private-key password=\"bubblegum\" >/somewhere/pk</private-key>"
        "<certificate>/elsewhere/cert</certificate>"
        "<ca-certificate/>"
        "<tpm-password>cherry</tpm-password>"
        "<akctx>/where/ctx</akctx>"
        "<akpubkey>/whereelse/pubkey</akpubkey>"
        "</credentials>";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(creds_cfg_str, xmlStrlen(creds_cfg_str));
    ck_assert(d != NULL);
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_credentials_config(0, root, &cfg), -1);
    ck_assert(cfg.privkey_pass == NULL);
    ck_assert(cfg.privkey_file == NULL);
    ck_assert(cfg.cert_file == NULL);
    ck_assert(cfg.cacert_file == NULL);
    ck_assert(cfg.tpmpass == NULL);
    ck_assert(cfg.akctx == NULL);
    ck_assert(cfg.akpubkey == NULL);
    xmlFreeDoc(d);

    creds_cfg_str =
        "<credentials>"
        "<private-key password=\"bubblegum\" >/somewhere/pk</private-key>"
        "<certificate>/elsewhere/cert</certificate>"
        "<ca-certificate>/whoknowswhere/ca-cert</ca-certificate>"
        "<tpm-password/>"
        "<akctx>/where/ctx</akctx>"
        "<akpubkey>/whereelse/pubkey</akpubkey>"
        "</credentials>";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(creds_cfg_str, xmlStrlen(creds_cfg_str));
    ck_assert(d != NULL);
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_credentials_config(0, root, &cfg), -1);
    ck_assert(cfg.privkey_pass == NULL);
    ck_assert(cfg.privkey_file == NULL);
    ck_assert(cfg.cert_file == NULL);
    ck_assert(cfg.cacert_file == NULL);
    ck_assert(cfg.tpmpass == NULL);
    ck_assert(cfg.akctx == NULL);
    ck_assert(cfg.akpubkey == NULL);
    xmlFreeDoc(d);

    // Redundant nodes
    creds_cfg_str =
        "<credentials>"
        "<private-key password=\"bubblegum\" >/somewhere/pk</private-key>"
        "<certificate>/elsewhere/cert</certificate>"
        "<ca-certificate>/whoknowswhere/ca-cert</ca-certificate>"
        "<private-key password=\"potato\" >thisHadBetterNotShowUp</private-key>"
        "</credentials>";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(creds_cfg_str, xmlStrlen(creds_cfg_str));
    ck_assert(d != NULL);
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_credentials_config(0, root, &cfg), -1);
    ck_assert(cfg.privkey_pass == NULL);
    ck_assert(cfg.privkey_file == NULL);
    ck_assert(cfg.cert_file == NULL);
    ck_assert(cfg.cacert_file == NULL);
    xmlFreeDoc(d);

    creds_cfg_str =
        "<credentials>"
        "<private-key password=\"bubblegum\" >/somewhere/pk</private-key>"
        "<certificate>/elsewhere/cert</certificate>"
        "<ca-certificate>/whoknowswhere/ca-cert</ca-certificate>"
        "<certificate>thisHadBetterNotShowUp</certificate>"
        "</credentials>";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(creds_cfg_str, xmlStrlen(creds_cfg_str));
    ck_assert(d != NULL);
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_credentials_config(0, root, &cfg), -1);
    ck_assert(cfg.privkey_pass == NULL);
    ck_assert(cfg.privkey_file == NULL);
    ck_assert(cfg.cert_file == NULL);
    ck_assert(cfg.cacert_file == NULL);
    xmlFreeDoc(d);

    // Allow multiple ca-certificates because one day we'll want that
}
END_TEST

START_TEST(test_load_metadata_config)
{
    char *meta_cfg_str = "<metadata type=\"asps\" dir=\"aspsDir\" />";
    am_config cfg = {0};
    xmlDoc *d = get_doc_from_blob(meta_cfg_str, xmlStrlen(meta_cfg_str));
    ck_assert(d != NULL);
    xmlNode *root = xmlDocGetRootElement(d);
    load_metadata_config(0, root, &cfg);
    ck_assert_str_eq(cfg.asp_metadata_dir, "aspsDir");
    ck_assert(cfg.apb_metadata_dir == NULL);
    ck_assert(cfg.mspec_dir == NULL);
    xmlFreeDoc(d);
    xmlFree(cfg.asp_metadata_dir);

    meta_cfg_str = "<metadata type=\"apbs\" dir=\"apbsDir\" />";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(meta_cfg_str, xmlStrlen(meta_cfg_str));
    ck_assert(d != NULL);
    root = xmlDocGetRootElement(d);
    load_metadata_config(0, root, &cfg);
    ck_assert(cfg.asp_metadata_dir == NULL);
    ck_assert_str_eq(cfg.apb_metadata_dir, "apbsDir");
    ck_assert(cfg.mspec_dir == NULL);
    xmlFreeDoc(d);
    xmlFree(cfg.apb_metadata_dir);

    meta_cfg_str = "<metadata type=\"measurement-specifications\" "
                   "dir=\"measurement-specificationsDir\" />";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(meta_cfg_str, xmlStrlen(meta_cfg_str));
    ck_assert(d != NULL);
    root = xmlDocGetRootElement(d);
    load_metadata_config(0, root, &cfg);
    ck_assert(cfg.asp_metadata_dir == NULL);
    ck_assert(cfg.apb_metadata_dir == NULL);
    ck_assert_str_eq(cfg.mspec_dir, "measurement-specificationsDir");
    xmlFreeDoc(d);
    xmlFree(cfg.mspec_dir);
}
END_TEST

START_TEST(test_load_invalid_metadata_config)
{
    char *meta_cfg_str = "<metadata/>";
    am_config cfg = {0};
    xmlDoc *d = get_doc_from_blob(meta_cfg_str, xmlStrlen(meta_cfg_str));
    ck_assert(d != NULL);
    xmlNode *root = xmlDocGetRootElement(d);
    load_metadata_config(0, root, &cfg);
    ck_assert(cfg.asp_metadata_dir == NULL);
    ck_assert(cfg.apb_metadata_dir == NULL);
    ck_assert(cfg.mspec_dir == NULL);
    xmlFreeDoc(d);

    meta_cfg_str = "<metadata type=\"unknown\" />";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(meta_cfg_str, xmlStrlen(meta_cfg_str));
    ck_assert(d != NULL);
    root = xmlDocGetRootElement(d);
    load_metadata_config(0, root, &cfg);
    ck_assert(cfg.asp_metadata_dir == NULL);
    ck_assert(cfg.apb_metadata_dir == NULL);
    ck_assert(cfg.mspec_dir == NULL);
    xmlFreeDoc(d);
}
END_TEST

START_TEST(test_load_selector_config)
{
    char *selector_cfg_str = "<selector source=\"file\">\n"
                             "<path>xmlContent</path>\n"
                             "</selector>";
    am_config cfg = {0};
    xmlDoc *d = get_doc_from_blob(selector_cfg_str, xmlStrlen(selector_cfg_str));
    ck_assert(d != NULL);
    xmlNode *root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_selector_config(0, root, &cfg), 0);
    ck_assert_str_eq(cfg.selector_source.method, SELECTOR_COPL);
    ck_assert_str_eq(cfg.selector_source.loc, "xmlContent");
    free(cfg.selector_source.method);
    xmlFree(cfg.selector_source.loc);
    xmlFreeDoc(d);

    // No extraneous whitespace
    selector_cfg_str = "<selector source=\"file\"><path>xmlContent</path>"
                       "</selector>";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(selector_cfg_str, xmlStrlen(selector_cfg_str));
    ck_assert(d != NULL);
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_selector_config(0, root, &cfg), 0);
    ck_assert_str_eq(cfg.selector_source.method, SELECTOR_COPL);
    ck_assert_str_eq(cfg.selector_source.loc, "xmlContent");
    free(cfg.selector_source.method);
    xmlFree(cfg.selector_source.loc);
    xmlFreeDoc(d);

    selector_cfg_str = "<selector source=\"mongo\">\n"
                       "<path>mongoContent</path>\n"
                       "</selector>";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(selector_cfg_str, xmlStrlen(selector_cfg_str));
    ck_assert(d != NULL);
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_selector_config(0, root, &cfg), 0);
    ck_assert_str_eq(cfg.selector_source.method, SELECTOR_MONGO);
    ck_assert_str_eq(cfg.selector_source.loc, "mongoContent");
    free(cfg.selector_source.method);
    xmlFree(cfg.selector_source.loc);
    xmlFreeDoc(d);

    // Pre-existing loc (e.g., from command line opts)
    selector_cfg_str = "<selector source=\"mongo\">\n"
                       "<path>mongoContent</path>\n"
                       "</selector>";
    bzero(&cfg, sizeof(cfg));
    cfg.selector_source.loc = "pre-existingLoc";
    d = get_doc_from_blob(selector_cfg_str, xmlStrlen(selector_cfg_str));
    ck_assert(d != NULL);
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_selector_config(0, root, &cfg), 0);
    ck_assert(cfg.selector_source.method == NULL);
    ck_assert_str_eq(cfg.selector_source.loc, "pre-existingLoc");
    xmlFreeDoc(d);
}
END_TEST

START_TEST(test_load_invalid_selector_config)
{
    char *selector_cfg_str = "<selector/>";
    am_config cfg = {0};
    xmlDoc *d = get_doc_from_blob(selector_cfg_str, xmlStrlen(selector_cfg_str));
    ck_assert(d != NULL);
    xmlNode *root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_selector_config(0, root, &cfg), -1);
    ck_assert(cfg.selector_source.method == NULL);
    ck_assert(cfg.selector_source.loc == NULL);
    xmlFreeDoc(d);

    // No path child node
    selector_cfg_str = "<selector source=\"mongo\">mongoContent</selector>";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(selector_cfg_str, xmlStrlen(selector_cfg_str));
    ck_assert(d != NULL);
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_selector_config(0, root, &cfg), -1);
    ck_assert(cfg.selector_source.method == NULL);
    ck_assert(cfg.selector_source.loc == NULL);
    xmlFreeDoc(d);

    // Missing content
    selector_cfg_str = "<selector source=\"mongo\" />";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(selector_cfg_str, xmlStrlen(selector_cfg_str));
    ck_assert(d != NULL);
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_selector_config(0, root, &cfg), -1);
    ck_assert(cfg.selector_source.method == NULL);
    ck_assert(cfg.selector_source.loc == NULL);
    xmlFreeDoc(d);

    // Unknown type
    selector_cfg_str = "<selector source=\"unknown\">\n"
                       "<path>unknownContent</path>\n"
                       "</selector>";
    bzero(&cfg, sizeof(cfg));
    d = get_doc_from_blob(selector_cfg_str, xmlStrlen(selector_cfg_str));
    ck_assert(d != NULL);
    root = xmlDocGetRootElement(d);
    ck_assert_int_eq(load_selector_config(0, root, &cfg), -1);
    ck_assert(cfg.selector_source.method == NULL);
    ck_assert(cfg.selector_source.loc == NULL);
    xmlFreeDoc(d);
}
END_TEST

START_TEST(test_attestmgr_load_full_config)
{
    // Oversize the buffer so there's plenty of room for user and group
    char cfg_str[2048] = "<?xml version=\"1.0\" ?>\n"
                         "<am-config>\n"
                         "<interfaces>\n"
                         "<interface type=\"inet\" address=\"0.0.0.0\" port=\"2342\" />\n"
                         "<interface type=\"unix\" path=\"/tmp/attestmgr.sock\" />\n"
                         "<interface type=\"unix\" path=\"/tmp/attestmgr-priv.sock\" skip-negotiation=\"true\" />\n"
                         "</interfaces>\n"
                         "<selector source=\"file\">\n"
                         "<path>/opt/maat/share/maat/selector-configurations/selector.xml</path>\n"
                         "</selector>\n"
                         "<credentials>\n"
                         "<private-key password=\"aPassword\">/opt/maat/etc/maat/credentials/client.key</private-key>\n"
                         "<certificate>/opt/maat/etc/maat/credentials/client.pem</certificate>\n"
                         "<ca-certificate>/opt/maat/etc/maat/credentials/ca.pem</ca-certificate>\n"
                         "<tpm-password>maatpass</tpm-password>\n"
                         "<akctx>/opt/maat/etc/maat/credentials/ak.ctx</akctx>\n"
                         "<akpubkey>/opt/maat/etc/maat/credentials/akpub.pem</akpubkey>\n"
                         "</credentials>\n"
                         "<metadata type=\"asps\" dir=\"/opt/maat/share/maat/asps\" />\n"
                         "<metadata type=\"apbs\" dir=\"/opt/maat/share/maat/apbs\" />\n"
                         "<metadata type=\"measurement-specifications\" dir=\"/opt/maat/share/maat/measurement-specifications\" />\n"
                         "<work dir=\"/tmp/attestmgr\" />\n"
                         "<timeout seconds=\"360\" />\n"
                         "<execcon_ignore_desired/>\n"
                         "<use_default_categories/>\n";

    uid_t uid = getuid();
    struct passwd *upwd = getpwuid(uid);
    ck_assert(upwd != NULL);
    ck_assert(upwd->pw_name != NULL);
    sprintf(cfg_str + strlen(cfg_str), "<user>%s</user>\n", upwd->pw_name);
    gid_t gid = getgid();
    struct group *grp = getgrgid(gid);
    ck_assert(grp != NULL);
    ck_assert(grp->gr_name != NULL);
    sprintf(cfg_str + strlen(cfg_str), "<group>%s</group>\n", grp->gr_name);
    strcat(cfg_str, "</am-config>");

    char cfg_path[] = __FILE__ "_tmpXXXXXX";
    int fd = mkstemp(cfg_path);
    ck_assert_int_gt(fd, 0);
    // fork & wait to guarantee cleanup of tmp file
    pid_t pid = fork();
    ck_assert(pid >= 0);
    if (pid == 0) {
        ck_assert_int_eq(write(fd, cfg_str, sizeof(cfg_str)), sizeof(cfg_str));
        ck_assert_int_eq(close(fd), 0);
        am_config cfg = {0};
        ck_assert_int_eq(attestmgr_load_config(cfg_path, &cfg), 0);

        // interfaces
        ck_assert(cfg.interfaces != NULL);
        GList *iface_node = cfg.interfaces;
        ck_assert(iface_node->data != NULL);
        am_iface_config *iface = iface_node->data;
        ck_assert(iface->type == INET);
        ck_assert(iface->address != NULL);
        ck_assert_str_eq(iface->address, "0.0.0.0");
        ck_assert_int_eq(iface->port, 2342);
        ck_assert(!iface->skip_negotiation);

        iface_node = iface_node->next;
        ck_assert(iface_node != NULL);
        ck_assert(iface_node->data != NULL);
        iface = iface_node->data;
        ck_assert(iface->type == UNIX);
        ck_assert(iface->address != NULL);
        ck_assert_str_eq(iface->address, "/tmp/attestmgr.sock");
        ck_assert(!iface->skip_negotiation);

        iface_node = iface_node->next;
        ck_assert(iface_node != NULL);
        ck_assert(iface_node->data != NULL);
        iface = iface_node->data;
        ck_assert(iface->type == UNIX);
        ck_assert(iface->address != NULL);
        ck_assert_str_eq(iface->address, "/tmp/attestmgr-priv.sock");
        ck_assert(iface->skip_negotiation);

        ck_assert(iface_node->next == NULL);

        // selector
        ck_assert_str_eq(cfg.selector_source.method, SELECTOR_COPL);
        ck_assert_str_eq(cfg.selector_source.loc, "/opt/maat/share/maat/selector-configurations/selector.xml");

        // credentials
        ck_assert_str_eq(cfg.privkey_pass, "aPassword");
        ck_assert_str_eq(cfg.privkey_file, "/opt/maat/etc/maat/credentials/client.key");
        ck_assert_str_eq(cfg.cert_file, "/opt/maat/etc/maat/credentials/client.pem");
        ck_assert_str_eq(cfg.cacert_file, "/opt/maat/etc/maat/credentials/ca.pem");
        ck_assert_str_eq(cfg.tpmpass, "maatpass");
        ck_assert_str_eq(cfg.akctx, "/opt/maat/etc/maat/credentials/ak.ctx");
        ck_assert_str_eq(cfg.akpubkey, "/opt/maat/etc/maat/credentials/akpub.pem");

        // metadata
        ck_assert_str_eq(cfg.asp_metadata_dir, "/opt/maat/share/maat/asps");
        ck_assert_str_eq(cfg.apb_metadata_dir, "/opt/maat/share/maat/apbs");
        ck_assert_str_eq(cfg.mspec_dir, "/opt/maat/share/maat/measurement-specifications");

        // work
        ck_assert_str_eq(cfg.workdir, "/tmp/attestmgr");

        // user
        ck_assert_int_eq(cfg.uid_set, 1);
        ck_assert_int_eq(cfg.uid, uid);

        // group
        ck_assert_int_eq(cfg.gid_set, 1);
        ck_assert_int_eq(cfg.gid, gid);

        // timeout
        ck_assert_int_eq(cfg.timeout_set, 1);
        ck_assert_int_eq(cfg.am_comm_timeout, 360);

        // execcon
        ck_assert(cfg.execcon_behavior == EXECCON_IGNORE_DESIRED);

        // categories
        ck_assert(cfg.use_unique_categories == EXECCON_USE_DEFAULT_CATEGORIES);

        free_am_config_data(&cfg);
    } else {
        int status = 0;
        waitpid(pid, &status, 0);
        unlink(cfg_path);
        if(WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            if (exit_code != 0) {
                exit(exit_code);
            }
        } else if (WIFSIGNALED(status)) {
            raise(WTERMSIG(status));
        } else {
            ck_abort_msg("attestmgr_load_config() terminated abnormally");
        }
    }
}
END_TEST

START_TEST(test_attestmgr_load_empty_config)
{
    char cfg_str[] = "<?xml version=\"1.0\" ?><am-config/>";
    char cfg_path[] = __FILE__ "_tmpXXXXXX";
    int fd = mkstemp(cfg_path);
    ck_assert_int_gt(fd, 0);
    // fork & wait to guarantee cleanup of tmp file
    pid_t pid = fork();
    ck_assert(pid >= 0);
    if (pid == 0) {
        ck_assert_int_eq(write(fd, cfg_str, sizeof(cfg_str)), sizeof(cfg_str));
        ck_assert_int_eq(close(fd), 0);
        am_config cfg = {0};
        ck_assert_int_eq(attestmgr_load_config(cfg_path, &cfg), 0);
        am_config empty_cfg = {0};
        ck_assert_int_eq(memcmp(&cfg, &empty_cfg, sizeof(cfg)), 0);
    } else {
        int status = 0;
        waitpid(pid, &status, 0);
        unlink(cfg_path);
        if(WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            if (exit_code != 0) {
                exit(exit_code);
            }
        } else if (WIFSIGNALED(status)) {
            raise(WTERMSIG(status));
        } else {
            ck_abort_msg("attestmgr_load_config() terminated abnormally");
        }
    }
}
END_TEST

START_TEST(test_attestmgr_load_invalid_config_bad_xml)
{
    char cfg_str[] = "?";
    char cfg_path[] = __FILE__ "_tmpXXXXXX";
    int fd = mkstemp(cfg_path);
    ck_assert_int_gt(fd, 0);
    // fork & wait to guarantee cleanup of tmp file
    pid_t pid = fork();
    ck_assert(pid >= 0);
    if (pid == 0) {
        ck_assert_int_eq(write(fd, cfg_str, sizeof(cfg_str)), sizeof(cfg_str));
        ck_assert_int_eq(close(fd), 0);
        am_config cfg = {0};
        ck_assert_int_eq(attestmgr_load_config(cfg_path, &cfg), -1);
        am_config empty_cfg = {0};
        ck_assert_int_eq(memcmp(&cfg, &empty_cfg, sizeof(cfg)), 0);
    } else {
        int status = 0;
        waitpid(pid, &status, 0);
        unlink(cfg_path);
        if(WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            if (exit_code != 0) {
                exit(exit_code);
            }
        } else if (WIFSIGNALED(status)) {
            raise(WTERMSIG(status));
        } else {
            ck_abort_msg("attestmgr_load_config() terminated abnormally");
        }
    }
}
END_TEST

START_TEST(test_attestmgr_load_invalid_config_wrong_root)
{
    char cfg_str[] = "<?xml version=\"1.0\" ?><am_config/>";
    char cfg_path[] = __FILE__ "_tmpXXXXXX";
    int fd = mkstemp(cfg_path);
    ck_assert_int_gt(fd, 0);
    // fork & wait to guarantee cleanup of tmp file
    pid_t pid = fork();
    ck_assert(pid >= 0);
    if (pid == 0) {
        ck_assert_int_eq(write(fd, cfg_str, sizeof(cfg_str)), sizeof(cfg_str));
        ck_assert_int_eq(close(fd), 0);
        am_config cfg = {0};
        ck_assert_int_eq(attestmgr_load_config(cfg_path, &cfg), -1);
        am_config empty_cfg = {0};
        ck_assert_int_eq(memcmp(&cfg, &empty_cfg, sizeof(cfg)), 0);
    } else {
        int status = 0;
        waitpid(pid, &status, 0);
        unlink(cfg_path);
        if(WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            if (exit_code != 0) {
                exit(exit_code);
            }
        } else if (WIFSIGNALED(status)) {
            raise(WTERMSIG(status));
        } else {
            ck_abort_msg("attestmgr_load_config() terminated abnormally");
        }
    }
}
END_TEST

START_TEST(test_attestmgr_load_invalid_config_bad_selector)
{
    char cfg_str[] = "<?xml version=\"1.0\" ?>\n"
                     "<am-config>\n"
                     "<selector source=\"file\">\n"
                     "Missing path child node\n"
                     "</selector>\n"
                     "</am-config>";
    char cfg_path[] = __FILE__ "_tmpXXXXXX";
    int fd = mkstemp(cfg_path);
    ck_assert_int_gt(fd, 0);
    // fork & wait to guarantee cleanup of tmp file
    pid_t pid = fork();
    ck_assert(pid >= 0);
    if (pid == 0) {
        ck_assert_int_eq(write(fd, cfg_str, sizeof(cfg_str)), sizeof(cfg_str));
        ck_assert_int_eq(close(fd), 0);
        am_config cfg = {0};
        ck_assert_int_eq(attestmgr_load_config(cfg_path, &cfg), -1);
        am_config empty_cfg = {0};
        ck_assert_int_eq(memcmp(&cfg, &empty_cfg, sizeof(cfg)), 0);
    } else {
        int status = 0;
        waitpid(pid, &status, 0);
        unlink(cfg_path);
        if(WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            if (exit_code != 0) {
                exit(exit_code);
            }
        } else if (WIFSIGNALED(status)) {
            raise(WTERMSIG(status));
        } else {
            ck_abort_msg("attestmgr_load_config() terminated abnormally");
        }
    }
}
END_TEST

START_TEST(test_attestmgr_load_invalid_config_bad_credentials)
{
    char cfg_str[] = "<?xml version=\"1.0\" ?>\n"
                     "<am-config>\n"
                     "<credentials>\n"
                     "<private-key/>\n"
                     "</credentials>\n"
                     "</am-config>";
    char cfg_path[] = __FILE__ "_tmpXXXXXX";
    int fd = mkstemp(cfg_path);
    ck_assert_int_gt(fd, 0);
    // fork & wait to guarantee cleanup of tmp file
    pid_t pid = fork();
    ck_assert(pid >= 0);
    if (pid == 0) {
        ck_assert_int_eq(write(fd, cfg_str, sizeof(cfg_str)), sizeof(cfg_str));
        ck_assert_int_eq(close(fd), 0);
        am_config cfg = {0};
        ck_assert_int_eq(attestmgr_load_config(cfg_path, &cfg), -1);
        am_config empty_cfg = {0};
        ck_assert_int_eq(memcmp(&cfg, &empty_cfg, sizeof(cfg)), 0);
    } else {
        int status = 0;
        waitpid(pid, &status, 0);
        unlink(cfg_path);
        if(WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            if (exit_code != 0) {
                exit(exit_code);
            }
        } else if (WIFSIGNALED(status)) {
            raise(WTERMSIG(status));
        } else {
            ck_abort_msg("attestmgr_load_config() terminated abnormally");
        }
    }
}
END_TEST

START_TEST(test_attestmgr_load_invalid_config_bad_user)
{
    char cfg_str[] = "<?xml version=\"1.0\" ?>\n"
                     "<am-config>\n"
                     "<user>aNonExistentUserIHope</user>\n"
                     "</am-config>";
    char cfg_path[] = __FILE__ "_tmpXXXXXX";
    int fd = mkstemp(cfg_path);
    ck_assert_int_gt(fd, 0);
    // fork & wait to guarantee cleanup of tmp file
    pid_t pid = fork();
    ck_assert(pid >= 0);
    if (pid == 0) {
        ck_assert_int_eq(write(fd, cfg_str, sizeof(cfg_str)), sizeof(cfg_str));
        ck_assert_int_eq(close(fd), 0);
        am_config cfg = {0};
        ck_assert_int_eq(attestmgr_load_config(cfg_path, &cfg), -1);
        am_config empty_cfg = {0};
        ck_assert_int_eq(memcmp(&cfg, &empty_cfg, sizeof(cfg)), 0);
    } else {
        int status = 0;
        waitpid(pid, &status, 0);
        unlink(cfg_path);
        if(WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            if (exit_code != 0) {
                exit(exit_code);
            }
        } else if (WIFSIGNALED(status)) {
            raise(WTERMSIG(status));
        } else {
            ck_abort_msg("attestmgr_load_config() terminated abnormally");
        }
    }
}
END_TEST

START_TEST(test_attestmgr_load_invalid_config_bad_group)
{
    char cfg_str[] = "<?xml version=\"1.0\" ?>\n"
                     "<am-config>\n"
                     "<group>aNonExistentGroupIHope</group>\n"
                     "</am-config>";
    char cfg_path[] = __FILE__ "_tmpXXXXXX";
    int fd = mkstemp(cfg_path);
    ck_assert_int_gt(fd, 0);
    // fork & wait to guarantee cleanup of tmp file
    pid_t pid = fork();
    ck_assert(pid >= 0);
    if (pid == 0) {
        ck_assert_int_eq(write(fd, cfg_str, sizeof(cfg_str)), sizeof(cfg_str));
        ck_assert_int_eq(close(fd), 0);
        am_config cfg = {0};
        ck_assert_int_eq(attestmgr_load_config(cfg_path, &cfg), -1);
        am_config empty_cfg = {0};
        ck_assert_int_eq(memcmp(&cfg, &empty_cfg, sizeof(cfg)), 0);
    } else {
        int status = 0;
        waitpid(pid, &status, 0);
        unlink(cfg_path);
        if(WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            if (exit_code != 0) {
                exit(exit_code);
            }
        } else if (WIFSIGNALED(status)) {
            raise(WTERMSIG(status));
        } else {
            ck_abort_msg("attestmgr_load_config() terminated abnormally");
        }
    }
}
END_TEST

START_TEST(test_attestmgr_load_invalid_config_bad_timeout)
{
    char cfg_str[] = "<?xml version=\"1.0\" ?>\n"
                     "<am-config>\n"
                     "<timeout/>\n"
                     "</am-config>";
    char cfg_path[] = __FILE__ "_tmpXXXXXX";
    int fd = mkstemp(cfg_path);
    ck_assert_int_gt(fd, 0);
    // fork & wait to guarantee cleanup of tmp file
    pid_t pid = fork();
    ck_assert(pid >= 0);
    if (pid == 0) {
        ck_assert_int_eq(write(fd, cfg_str, sizeof(cfg_str)), sizeof(cfg_str));
        ck_assert_int_eq(close(fd), 0);
        am_config cfg = {0};
        ck_assert_int_eq(attestmgr_load_config(cfg_path, &cfg), -1);
        am_config empty_cfg = {0};
        ck_assert_int_eq(memcmp(&cfg, &empty_cfg, sizeof(cfg)), 0);
    } else {
        int status = 0;
        waitpid(pid, &status, 0);
        unlink(cfg_path);
        if(WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            if (exit_code != 0) {
                exit(exit_code);
            }
        } else if (WIFSIGNALED(status)) {
            raise(WTERMSIG(status));
        } else {
            ck_abort_msg("attestmgr_load_config() terminated abnormally");
        }
    }
}
END_TEST

int main(void)
{
    Suite *suite;
    SRunner *runner;
    TCase *am_config_tests;
    int nfail;

    suite = suite_create("am_config");
    am_config_tests = tcase_create("am_config");

    tcase_add_test(am_config_tests, test_load_inet_iface_config);
    tcase_add_test(am_config_tests, test_load_invalid_inet_iface_config);

    tcase_add_test(am_config_tests, test_load_unix_iface_config);
    tcase_add_test(am_config_tests, test_load_invalid_unix_iface_config);

    tcase_add_test(am_config_tests, test_load_iface_configs);
    tcase_add_test(am_config_tests, test_load_invalid_iface_configs);

    tcase_add_test(am_config_tests, test_load_credentials_config);
    tcase_add_test(am_config_tests, test_load_invalid_credentials_config);

    tcase_add_test(am_config_tests, test_load_metadata_config);
    tcase_add_test(am_config_tests, test_load_invalid_metadata_config);

    tcase_add_test(am_config_tests, test_load_selector_config);
    tcase_add_test(am_config_tests, test_load_invalid_selector_config);

    tcase_add_test(am_config_tests, test_attestmgr_load_full_config);
    tcase_add_test(am_config_tests, test_attestmgr_load_empty_config);
    tcase_add_test(am_config_tests, test_attestmgr_load_invalid_config_bad_xml);
    tcase_add_test(am_config_tests, test_attestmgr_load_invalid_config_wrong_root);
    tcase_add_test(am_config_tests, test_attestmgr_load_invalid_config_bad_selector);
    tcase_add_test(am_config_tests, test_attestmgr_load_invalid_config_bad_credentials);
    tcase_add_test(am_config_tests, test_attestmgr_load_invalid_config_bad_user);
    tcase_add_test(am_config_tests, test_attestmgr_load_invalid_config_bad_group);
    tcase_add_test(am_config_tests, test_attestmgr_load_invalid_config_bad_timeout);

    suite_add_tcase(suite, am_config_tests);

    runner = srunner_create(suite);
    srunner_set_log(runner, "test_am_config.log");
    srunner_set_xml(runner, "test_am_config.xml");
    srunner_run_all(runner, CK_VERBOSE);
    nfail = srunner_ntests_failed(runner);
    if(runner) srunner_free(runner);
    return nfail;

}
