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


#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <check.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>

#include <maat-envvars.h>
#include <am/am_config.h>

char *get_user_name(void)
{
    uid_t uid = getuid();
    struct passwd *upwd = getpwuid(uid);
    ck_assert(upwd != NULL);
    ck_assert(upwd->pw_name != NULL);
    return upwd->pw_name;
}

char *get_group_name(void)
{
    gid_t gid = getgid();
    struct group *grp = getgrgid(gid);
    ck_assert(grp != NULL);
    ck_assert(grp->gr_name != NULL);
    return grp->gr_name;
}

void cleanup_config(am_config *cfg)
{
    g_list_free_full(cfg->interfaces, (GDestroyNotify)free_am_iface_config);
    free(cfg->asp_metadata_dir);
    free(cfg->apb_metadata_dir);
    free(cfg->mspec_dir);
    free(cfg->selector_source.method);
    free(cfg->selector_source.loc);
    free(cfg->workdir);
    free(cfg->cacert_file);
    free(cfg->cert_file);
    free(cfg->privkey_file);
}

START_TEST(test_attestmgr_getopt)
{
    // Minimal
    char *argv[] = {
        "attestmgr",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file"
    };
    int argc = sizeof(argv)/sizeof(*argv);
    am_config cfg = {0};
    ck_assert_int_eq(attestmgr_getopt(argc, argv, &cfg), 0);

    ck_assert(cfg.interfaces == NULL);
    ck_assert_int_eq(cfg.timeout_set, 0);
    ck_assert_int_eq(cfg.uid_set, 0);
    ck_assert_int_eq(cfg.uid, 0);
    ck_assert_int_eq(cfg.gid_set, 0);
    ck_assert_int_eq(cfg.gid, 0);
    ck_assert_int_eq(cfg.am_comm_timeout, DEFAULT_AM_COMM_TIMEOUT);
    ck_assert_str_eq(cfg.asp_metadata_dir, DEFAULT_ASP_DIR);
    ck_assert_str_eq(cfg.apb_metadata_dir, DEFAULT_APB_DIR);
    ck_assert_str_eq(cfg.mspec_dir, DEFAULT_MEAS_SPEC_DIR);
    ck_assert_str_eq(cfg.selector_source.method, SELECTOR_COPL);
    ck_assert_str_eq(cfg.selector_source.loc, DEFAULT_SELECTOR_PATH);
    char default_workdir[PATH_MAX];
    snprintf(default_workdir, PATH_MAX, "/tmp/attestmgr_workdir.%d", getpid());
    ck_assert_str_eq(cfg.workdir, default_workdir);
    ck_assert_str_eq(cfg.cacert_file, "a_CA_cert_file");
    ck_assert_str_eq(cfg.cert_file, "a_cert_file");
    ck_assert_str_eq(cfg.privkey_file, "a_private_key_file");
    ck_assert_int_eq(cfg.execcon_behavior, 0);
    ck_assert_int_eq(cfg.use_unique_categories, 0);
    cleanup_config(&cfg);

    // Complete
    optind = 1;
    char *full_argv[] = {
        "attestmgr",
        "-i", "127.0.0.1:1234",
        "-U", get_user_name(),
        "-G", get_group_name(),
        "-u", "unix_iface_path",
        "-t", "1",
        "-s", "a_selector_loc",
        "-m", "a_selector_method",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file",
        "-S", "an_asp_metadata_dir",
        "-I", "an_apb_metadata_dir",
        "-M", "an_mspec_dir",
        "-w", "a_workdir",
        "-X",
        "-Z"
    };
    argc = sizeof(full_argv)/sizeof(*full_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, full_argv, &cfg), 0);

    GList *iface_node = cfg.interfaces;
    ck_assert(iface_node != NULL);
    am_iface_config *iface = iface_node->data;
    ck_assert(iface != NULL);
    ck_assert(iface->type == INET);
    ck_assert(iface->address != NULL);
    ck_assert_str_eq(iface->address, "127.0.0.1");
    ck_assert_int_eq(iface->port, 1234);
    ck_assert_int_eq(iface->skip_negotiation, 0);
    ck_assert(iface_node->next != NULL);

    iface_node = iface_node->next;
    ck_assert(iface_node != NULL);
    iface = iface_node->data;
    ck_assert(iface != NULL);
    ck_assert(iface->type == UNIX);
    ck_assert(iface->address != NULL);
    ck_assert_str_eq(iface->address, "unix_iface_path");
    ck_assert_int_eq(iface->port, 0);
    ck_assert_int_eq(iface->skip_negotiation, 0);
    ck_assert(iface_node->next == NULL);

    ck_assert_int_eq(cfg.uid_set, 1);
    ck_assert_int_eq(cfg.uid, getuid());
    ck_assert_int_eq(cfg.gid_set, 1);
    ck_assert_int_eq(cfg.gid, getgid());
    ck_assert_int_eq(cfg.am_comm_timeout, 1);
    ck_assert_int_eq(cfg.timeout_set, 1);

    ck_assert_str_eq(cfg.selector_source.loc, "a_selector_loc");
    ck_assert_str_eq(cfg.selector_source.method, "a_selector_method");
    ck_assert_str_eq(cfg.cacert_file, "a_CA_cert_file");
    ck_assert_str_eq(cfg.cert_file, "a_cert_file");
    ck_assert_str_eq(cfg.privkey_file, "a_private_key_file");
    ck_assert_str_eq(cfg.asp_metadata_dir, "an_asp_metadata_dir");
    ck_assert_str_eq(cfg.apb_metadata_dir, "an_apb_metadata_dir");
    ck_assert_str_eq(cfg.mspec_dir, "an_mspec_dir");
    ck_assert_str_eq(cfg.workdir, "a_workdir");
    ck_assert_int_eq(cfg.execcon_behavior, EXECCON_IGNORE_DESIRED);
    ck_assert_int_eq(cfg.use_unique_categories, EXECCON_USE_DEFAULT_CATEGORIES);
    cleanup_config(&cfg);

    // Environment variables
    optind = 1;
    char *env_argv[] = {
        "attestmgr",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file"
    };
    argc = sizeof(env_argv)/sizeof(*env_argv);
    bzero(&cfg, sizeof(cfg));

    setenv(ENV_MAAT_IGNORE_DESIRED_CONTEXTS, "no", 1);
    setenv(ENV_MAAT_USE_DEFAULT_CATEGORIES, "no", 1);
    setenv(ENV_MAAT_ASP_DIR, "env_asp_dir", 1);
    setenv(ENV_MAAT_APB_DIR, "env_apb_dir", 1);
    setenv(ENV_MAAT_MEAS_SPEC_DIR, "env_meas_spec_dir", 1);
    setenv(ENV_MAAT_SELECTOR_METHOD, "env_selector_method", 1);
    setenv(ENV_MAAT_SELECTOR_PATH, "env_selector_path", 1);

    ck_assert_int_eq(attestmgr_getopt(argc, env_argv, &cfg), 0);

    unsetenv(ENV_MAAT_IGNORE_DESIRED_CONTEXTS);
    unsetenv(ENV_MAAT_USE_DEFAULT_CATEGORIES);
    unsetenv(ENV_MAAT_ASP_DIR);
    unsetenv(ENV_MAAT_APB_DIR);
    unsetenv(ENV_MAAT_MEAS_SPEC_DIR);
    unsetenv(ENV_MAAT_SELECTOR_METHOD);
    unsetenv(ENV_MAAT_SELECTOR_PATH);

    ck_assert_str_eq(cfg.cacert_file, "a_CA_cert_file");
    ck_assert_str_eq(cfg.cert_file, "a_cert_file");
    ck_assert_str_eq(cfg.privkey_file, "a_private_key_file");

    ck_assert_int_eq(cfg.execcon_behavior, EXECCON_IGNORE_DESIRED);
    ck_assert_int_eq(cfg.use_unique_categories, EXECCON_USE_DEFAULT_CATEGORIES);
    ck_assert_str_eq(cfg.asp_metadata_dir, "env_asp_dir");
    ck_assert_str_eq(cfg.apb_metadata_dir, "env_apb_dir");
    ck_assert_str_eq(cfg.mspec_dir, "env_meas_spec_dir");
    ck_assert_str_eq(cfg.selector_source.method, "env_selector_method");
    ck_assert_str_eq(cfg.selector_source.loc, "env_selector_path");

    ck_assert(cfg.interfaces == NULL);
    ck_assert_int_eq(cfg.timeout_set, 0);
    ck_assert_int_eq(cfg.uid_set, 0);
    ck_assert_int_eq(cfg.uid, 0);
    ck_assert_int_eq(cfg.gid_set, 0);
    ck_assert_int_eq(cfg.gid, 0);
    ck_assert_int_eq(cfg.am_comm_timeout, DEFAULT_AM_COMM_TIMEOUT);
    ck_assert_str_eq(cfg.workdir, default_workdir);
    cleanup_config(&cfg);
}
END_TEST

START_TEST(test_attestmgr_getopt_full_config_xml)
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
                         "<tpm-password>cherry</tpm-password>\n"
                         "</credentials>\n"
                         "<metadata type=\"asps\" dir=\"/opt/maat/share/maat/asps\" />\n"
                         "<metadata type=\"apbs\" dir=\"/opt/maat/share/maat/apbs\" />\n"
                         "<metadata type=\"measurement-specifications\" dir=\"/opt/maat/share/maat/measurement-specifications\" />\n"
                         "<work dir=\"/tmp/attestmgr\" />\n"
                         "<timeout seconds=\"360\" />\n"
                         "<execcon_ignore_desired/>\n"
                         "<use_default_categories/>\n";

    sprintf(cfg_str + strlen(cfg_str), "<user>%s</user>\n", get_user_name());
    sprintf(cfg_str + strlen(cfg_str), "<group>%s</group>\n", get_group_name());
    strcat(cfg_str, "</am-config>");

    char cfg_path[] = __FILE__ "_tmpXXXXXX";
    int fd = mkstemp(cfg_path);
    ck_assert_int_gt(fd, 0);
    ck_assert_int_eq(write(fd, cfg_str, sizeof(cfg_str)), sizeof(cfg_str));
    ck_assert_int_eq(close(fd), 0);
    // fork & wait to guarantee cleanup of tmp file
    pid_t pid = fork();
    ck_assert(pid >= 0);
    if (pid == 0) {
        optind = 1;
        char *argv[] = {
            "attestmgr",
            "-C", cfg_path
        };
        int argc = sizeof(argv)/sizeof(*argv);
        am_config cfg = {0};
        ck_assert_int_eq(attestmgr_getopt(argc, argv, &cfg), 0);

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
        ck_assert_str_eq(cfg.tpm_pass, "cherry");

        // metadata
        ck_assert_str_eq(cfg.asp_metadata_dir, "/opt/maat/share/maat/asps");
        ck_assert_str_eq(cfg.apb_metadata_dir, "/opt/maat/share/maat/apbs");
        ck_assert_str_eq(cfg.mspec_dir, "/opt/maat/share/maat/measurement-specifications");

        // work
        ck_assert_str_eq(cfg.workdir, "/tmp/attestmgr");

        // user
        ck_assert_int_eq(cfg.uid_set, 1);
        ck_assert_int_eq(cfg.uid, getuid());

        // group
        ck_assert_int_eq(cfg.gid_set, 1);
        ck_assert_int_eq(cfg.gid, getgid());

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

START_TEST(test_attestmgr_getopt_opts_trump_all)
{
    // Config XML that should get trumped
    char cfg_str[] = "<?xml version=\"1.0\" ?>\n"
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
                     "</credentials>\n"
                     "<metadata type=\"asps\" dir=\"/opt/maat/share/maat/asps\" />\n"
                     "<metadata type=\"apbs\" dir=\"/opt/maat/share/maat/apbs\" />\n"
                     "<metadata type=\"measurement-specifications\" dir=\"/opt/maat/share/maat/measurement-specifications\" />\n"
                     "<tpm-password>cherry></tpm-password>"
                     "<work dir=\"/tmp/attestmgr\" />\n"
                     "<timeout seconds=\"360\" />\n"
                     "<user>thisIsNotAUser</user>\n"
                     "<group>thisIsNotAGroup</group>\n"
                     "</am-config>";

    char cfg_path[] = __FILE__ "_tmpXXXXXX";
    int fd = mkstemp(cfg_path);
    ck_assert_int_gt(fd, 0);
    ck_assert_int_eq(write(fd, cfg_str, sizeof(cfg_str)), sizeof(cfg_str));
    ck_assert_int_eq(close(fd), 0);
    // fork & wait to guarantee cleanup of tmp file
    pid_t pid = fork();
    ck_assert(pid >= 0);
    if (pid == 0) {
        optind = 1;
        char *full_argv[] = {
            "attestmgr",
            "-C", cfg_path,
            "-i", "127.0.0.1:1234",
            "-U", get_user_name(),
            "-G", get_group_name(),
            "-u", "unix_iface_path",
            "-t", "1",
            "-s", "a_selector_loc",
            "-m", "a_selector_method",
            "-a", "a_CA_cert_file",
            "-f", "a_cert_file",
            "-k", "a_private_key_file",
            "-S", "an_asp_metadata_dir",
            "-I", "an_apb_metadata_dir",
            "-M", "an_mspec_dir",
            "-w", "a_workdir",
            "-X",
            "-Z"
        };
        int argc = sizeof(full_argv)/sizeof(*full_argv);
        am_config cfg = {0};
        ck_assert_int_eq(attestmgr_getopt(argc, full_argv, &cfg), 0);

        GList *iface_node = cfg.interfaces;
        ck_assert(iface_node != NULL);
        am_iface_config *iface = iface_node->data;
        ck_assert(iface != NULL);
        ck_assert(iface->type == INET);
        ck_assert(iface->address != NULL);
        ck_assert_str_eq(iface->address, "127.0.0.1");
        ck_assert_int_eq(iface->port, 1234);
        ck_assert_int_eq(iface->skip_negotiation, 0);
        ck_assert(iface_node->next != NULL);

        iface_node = iface_node->next;
        ck_assert(iface_node != NULL);
        iface = iface_node->data;
        ck_assert(iface != NULL);
        ck_assert(iface->type == UNIX);
        ck_assert(iface->address != NULL);
        ck_assert_str_eq(iface->address, "unix_iface_path");
        ck_assert_int_eq(iface->port, 0);
        ck_assert_int_eq(iface->skip_negotiation, 0);
        ck_assert(iface_node->next == NULL);

        ck_assert_int_eq(cfg.uid_set, 1);
        ck_assert_int_eq(cfg.uid, getuid());
        ck_assert_int_eq(cfg.gid_set, 1);
        ck_assert_int_eq(cfg.gid, getgid());
        ck_assert_int_eq(cfg.am_comm_timeout, 1);
        ck_assert_int_eq(cfg.timeout_set, 1);

        ck_assert_str_eq(cfg.selector_source.loc, "a_selector_loc");
        ck_assert_str_eq(cfg.selector_source.method, "a_selector_method");
        ck_assert_str_eq(cfg.cacert_file, "a_CA_cert_file");
        ck_assert_str_eq(cfg.cert_file, "a_cert_file");
        ck_assert_str_eq(cfg.privkey_file, "a_private_key_file");
        ck_assert_str_eq(cfg.asp_metadata_dir, "an_asp_metadata_dir");
        ck_assert_str_eq(cfg.apb_metadata_dir, "an_apb_metadata_dir");
        ck_assert_str_eq(cfg.mspec_dir, "an_mspec_dir");
        ck_assert_str_eq(cfg.workdir, "a_workdir");
        ck_assert_int_eq(cfg.execcon_behavior, EXECCON_IGNORE_DESIRED);
        ck_assert_int_eq(cfg.use_unique_categories, EXECCON_USE_DEFAULT_CATEGORIES);
        cleanup_config(&cfg);
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

START_TEST(test_attestmgr_getopt_env_trumps_config)
{
    // Config XML that should get trumped
    char cfg_str[] = "<?xml version=\"1.0\" ?>\n"
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
                     "</credentials>\n"
                     "<metadata type=\"asps\" dir=\"/opt/maat/share/maat/asps\" />\n"
                     "<metadata type=\"apbs\" dir=\"/opt/maat/share/maat/apbs\" />\n"
                     "<metadata type=\"measurement-specifications\" dir=\"/opt/maat/share/maat/measurement-specifications\" />\n"
                     "<work dir=\"/tmp/attestmgr\" />\n"
                     "<timeout seconds=\"360\" />\n"
                     "<user>thisIsNotAUser</user>\n"
                     "<group>thisIsNotAGroup</group>\n"
                     "</am-config>";

    char cfg_path[] = __FILE__ "_tmpXXXXXX";
    int fd = mkstemp(cfg_path);
    ck_assert_int_gt(fd, 0);
    ck_assert_int_eq(write(fd, cfg_str, sizeof(cfg_str)), sizeof(cfg_str));
    ck_assert_int_eq(close(fd), 0);
    // fork & wait to guarantee cleanup of tmp file
    pid_t pid = fork();
    ck_assert(pid >= 0);
    if (pid == 0) {
        optind = 1;
        char *argv[] = {
            "attestmgr",
            "-C", cfg_path,
            "-i", "127.0.0.1:1234",
            "-U", get_user_name(),
            "-G", get_group_name(),
            "-u", "unix_iface_path",
            "-t", "1",
            "-a", "a_CA_cert_file",
            "-f", "a_cert_file",
            "-k", "a_private_key_file",
            "-w", "a_workdir"
        };
        int argc = sizeof(argv)/sizeof(*argv);
        am_config cfg = {0};

        setenv(ENV_MAAT_IGNORE_DESIRED_CONTEXTS, "no", 1);
        setenv(ENV_MAAT_USE_DEFAULT_CATEGORIES, "no", 1);
        setenv(ENV_MAAT_ASP_DIR, "env_asp_dir", 1);
        setenv(ENV_MAAT_APB_DIR, "env_apb_dir", 1);
        setenv(ENV_MAAT_MEAS_SPEC_DIR, "env_meas_spec_dir", 1);
        setenv(ENV_MAAT_SELECTOR_METHOD, "env_selector_method", 1);
        setenv(ENV_MAAT_SELECTOR_PATH, "env_selector_path", 1);

        ck_assert_int_eq(attestmgr_getopt(argc, argv, &cfg), 0);

        unsetenv(ENV_MAAT_IGNORE_DESIRED_CONTEXTS);
        unsetenv(ENV_MAAT_USE_DEFAULT_CATEGORIES);
        unsetenv(ENV_MAAT_ASP_DIR);
        unsetenv(ENV_MAAT_APB_DIR);
        unsetenv(ENV_MAAT_MEAS_SPEC_DIR);
        unsetenv(ENV_MAAT_SELECTOR_METHOD);
        unsetenv(ENV_MAAT_SELECTOR_PATH);

        ck_assert_int_eq(cfg.execcon_behavior, EXECCON_IGNORE_DESIRED);
        ck_assert_int_eq(cfg.use_unique_categories, EXECCON_USE_DEFAULT_CATEGORIES);
        ck_assert_str_eq(cfg.asp_metadata_dir, "env_asp_dir");
        ck_assert_str_eq(cfg.apb_metadata_dir, "env_apb_dir");
        ck_assert_str_eq(cfg.mspec_dir, "env_meas_spec_dir");
        ck_assert_str_eq(cfg.selector_source.method, "env_selector_method");
        ck_assert_str_eq(cfg.selector_source.loc, "env_selector_path");

        GList *iface_node = cfg.interfaces;
        ck_assert(iface_node != NULL);
        am_iface_config *iface = iface_node->data;
        ck_assert(iface != NULL);
        ck_assert(iface->type == INET);
        ck_assert(iface->address != NULL);
        ck_assert_str_eq(iface->address, "127.0.0.1");
        ck_assert_int_eq(iface->port, 1234);
        ck_assert_int_eq(iface->skip_negotiation, 0);
        ck_assert(iface_node->next != NULL);

        iface_node = iface_node->next;
        ck_assert(iface_node != NULL);
        iface = iface_node->data;
        ck_assert(iface != NULL);
        ck_assert(iface->type == UNIX);
        ck_assert(iface->address != NULL);
        ck_assert_str_eq(iface->address, "unix_iface_path");
        ck_assert_int_eq(iface->port, 0);
        ck_assert_int_eq(iface->skip_negotiation, 0);
        ck_assert(iface_node->next == NULL);

        ck_assert_int_eq(cfg.uid_set, 1);
        ck_assert_int_eq(cfg.uid, getuid());
        ck_assert_int_eq(cfg.gid_set, 1);
        ck_assert_int_eq(cfg.gid, getgid());
        ck_assert_int_eq(cfg.am_comm_timeout, 1);
        ck_assert_int_eq(cfg.timeout_set, 1);

        ck_assert_str_eq(cfg.cacert_file, "a_CA_cert_file");
        ck_assert_str_eq(cfg.cert_file, "a_cert_file");
        ck_assert_str_eq(cfg.privkey_file, "a_private_key_file");
        ck_assert_str_eq(cfg.workdir, "a_workdir");
        cleanup_config(&cfg);
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

START_TEST(test_attestmgr_getopt_fail)
{
    // No opts
    optind = 1;
    char *bin_name_argv[] = { "attestmgr" };
    int argc = sizeof(bin_name_argv)/sizeof(*bin_name_argv);
    am_config cfg = {0};
    ck_assert_int_eq(attestmgr_getopt(argc, bin_name_argv, &cfg), -1);

    // Help
    optind = 1;
    char *h_argv[] = { "attestmgr", "-h" };
    argc = sizeof(h_argv)/sizeof(*h_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, h_argv, &cfg), -1);

    optind = 1;
    char *help_argv[] = { "attestmgr", "--help" };
    argc = sizeof(help_argv)/sizeof(*help_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, help_argv, &cfg), -1);

    // Invalid interface
    optind = 1;
    char *invalid_inet_argv[] = {
        "attestmgr",
        "-i", "",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file"
    };
    argc = sizeof(invalid_inet_argv)/sizeof(*invalid_inet_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, invalid_inet_argv, &cfg), -1);

    // Invalid IP address on inet interface
    optind = 1;
    char *add_inet_argv[] = {
        "attestmgr",
        "-i", "127.0.0.256",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file"
    };
    argc = sizeof(add_inet_argv)/sizeof(*add_inet_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, add_inet_argv, &cfg), -1);

    // Invalid user
    optind = 1;
    char *user_argv[] = {
        "attestmgr",
        "-U", "guaranteedInvalidUser",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file"
    };
    argc = sizeof(user_argv)/sizeof(*user_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, user_argv, &cfg), -1);

    // Redundant user arg
    optind = 1;
    char *rpt_user_argv[] = {
        "attestmgr",
        "-U", get_user_name(),
        "-U", get_user_name(),
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file"
    };
    argc = sizeof(rpt_user_argv)/sizeof(*rpt_user_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, rpt_user_argv, &cfg), -1);

    // Invalid group
    optind = 1;
    char *group_argv[] = {
        "attestmgr",
        "-G", "guaranteedInvalidGroup",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file"
    };
    argc = sizeof(group_argv)/sizeof(*group_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, group_argv, &cfg), -1);

    // Redundant group arg
    optind = 1;
    char *rpt_group_argv[] = {
        "attestmgr",
        "-G", get_group_name(),
        "-G", get_group_name(),
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file"
    };
    argc = sizeof(rpt_group_argv)/sizeof(*rpt_group_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, rpt_group_argv, &cfg), -1);

    // Invalid timeout value
    optind = 1;
    char *empty_timeout_argv[] = {
        "attestmgr",
        "-t", "",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file"
    };
    argc = sizeof(empty_timeout_argv)/sizeof(*empty_timeout_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, empty_timeout_argv, &cfg), -1);

    optind = 1;
    char *neg_timeout_argv[] = {
        "attestmgr",
        "-t", "-1",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file"
    };
    argc = sizeof(neg_timeout_argv)/sizeof(*neg_timeout_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, neg_timeout_argv, &cfg), -1);

    optind = 1;
    char *alpha_timeout_argv[] = {
        "attestmgr",
        "-t", "abc123",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file"
    };
    argc = sizeof(alpha_timeout_argv)/sizeof(*alpha_timeout_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, alpha_timeout_argv, &cfg), -1);

    optind = 1;
    char *ia_timeout_argv[] = {
        "attestmgr",
        "-t", "1a",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file"
    };
    argc = sizeof(ia_timeout_argv)/sizeof(*ia_timeout_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, ia_timeout_argv, &cfg), -1);

    optind = 1;
    char huge_timeout[32];
    ck_assert_int_gt(sprintf(huge_timeout, "%d",
                             MAX_AM_COMM_TIMEOUT + 1), 0);
    char *omax_timeout_argv[] = {
        "attestmgr",
        "-t", huge_timeout,
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file"
    };
    argc = sizeof(omax_timeout_argv)/sizeof(*omax_timeout_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, omax_timeout_argv, &cfg), -1);

    // Redundant timeout arg
    optind = 1;
    char *rpt_timeout_argv[] = {
        "attestmgr",
        "-t", "1",
        "-t", "2",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file"
    };
    argc = sizeof(rpt_timeout_argv)/sizeof(*rpt_timeout_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, rpt_timeout_argv, &cfg), -1);

    // Unknown arg
    optind = 1;
    char *unk_argv[] = {
        "attestmgr",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file",
        "--didntSeeThisComingDidYou"
    };
    argc = sizeof(unk_argv)/sizeof(*unk_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, unk_argv, &cfg), -1);

    // Selector source but no method
    optind = 1;
    char *loc_no_method_argv[] = {
        "attestmgr",
        "-s", "a_selector_loc",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file"
    };
    argc = sizeof(loc_no_method_argv)/sizeof(*loc_no_method_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, loc_no_method_argv, &cfg), -1);

    // Redundant selector loc
    optind = 1;
    char *rpt_loc_argv[] = {
        "attestmgr",
        "-s", "some_loc",
        "-s", "some_other_loc",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file"
    };
    argc = sizeof(rpt_loc_argv)/sizeof(*rpt_loc_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, rpt_loc_argv, &cfg), -1);

    // Redundant selector method
    optind = 1;
    char *rpt_method_argv[] = {
        "attestmgr",
        "-m", "some_method",
        "-m", "some_other_method",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file"
    };
    argc = sizeof(rpt_method_argv)/sizeof(*rpt_method_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, rpt_method_argv, &cfg), -1);

    // Redundant CA cert
    optind = 1;
    char *rpt_cacert_argv[] = {
        "attestmgr",
        "-a", "a_CA_cert_file",
        "-a", "some_other_CA_cert",
        "-f", "a_cert_file",
        "-k", "a_private_key_file"
    };
    argc = sizeof(rpt_cacert_argv)/sizeof(*rpt_cacert_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, rpt_cacert_argv, &cfg), -1);

    // Redundant cert
    optind = 1;
    char *rpt_cert_argv[] = {
        "attestmgr",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-f", "some_other_cert",
        "-k", "a_private_key_file"
    };
    argc = sizeof(rpt_cert_argv)/sizeof(*rpt_cert_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, rpt_cert_argv, &cfg), -1);

    // Redundant privkey
    optind = 1;
    char *rpt_privkey_argv[] = {
        "attestmgr",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file",
        "-k", "some_other_privkey"
    };
    argc = sizeof(rpt_privkey_argv)/sizeof(*rpt_privkey_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, rpt_privkey_argv, &cfg), -1);

    // Redundant ASP metadata dir
    optind = 1;
    char *rpt_asp_dir_argv[] = {
        "attestmgr",
        "-S", "an_asp_metadata_dir",
        "-S", "some_other_metadata_dir",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file"
    };
    argc = sizeof(rpt_asp_dir_argv)/sizeof(*rpt_asp_dir_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, rpt_asp_dir_argv, &cfg), -1);

    // Redundant APB metadata dir
    optind = 1;
    char *rpt_apb_dir_argv[] = {
        "attestmgr",
        "-I", "an_apb_metadata_dir",
        "-I", "some_other_metadata_dir",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file"
    };
    argc = sizeof(rpt_apb_dir_argv)/sizeof(*rpt_apb_dir_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, rpt_apb_dir_argv, &cfg), -1);

    // Redundant measurement spec dir
    optind = 1;
    char *rpt_mspec_dir_argv[] = {
        "attestmgr",
        "-M", "an_mspec_dir",
        "-M", "some_other_mspec_dir",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file"
    };
    argc = sizeof(rpt_mspec_dir_argv)/sizeof(*rpt_mspec_dir_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, rpt_mspec_dir_argv, &cfg), -1);

    // Redundant work dir
    optind = 1;
    char *rpt_workdir_argv[] = {
        "attestmgr",
        "-w", "a_workdir",
        "-w", "some_other_workdir",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file"
    };
    argc = sizeof(rpt_workdir_argv)/sizeof(*rpt_workdir_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, rpt_workdir_argv, &cfg), -1);

    // No CA cert
    optind = 1;
    char *no_cacert_argv[] = {
        "attestmgr",
        "-f", "a_cert_file"
        "-k", "a_private_key_file"
    };
    argc = sizeof(no_cacert_argv)/sizeof(*no_cacert_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, no_cacert_argv, &cfg), -1);

    // No privkey file
    optind = 1;
    char *no_privkey_argv[] = {
        "attestmgr",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file"
    };
    argc = sizeof(no_privkey_argv)/sizeof(*no_privkey_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, no_privkey_argv, &cfg), -1);

    // No cert
    optind = 1;
    char *no_cert_argv[] = {
        "attestmgr",
        "-a", "a_CA_cert_file",
        "-k", "a_private_key_file"
    };
    argc = sizeof(no_cert_argv)/sizeof(*no_cert_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, no_cert_argv, &cfg), -1);

    // Invalid config file
    optind = 1;
    char *invalid_config_argv[] = {
        "attestmgr",
        "-a", "a_CA_cert_file",
        "-f", "a_cert_file",
        "-k", "a_private_key_file",
        "-C", "invalid_config_file"
    };
    argc = sizeof(invalid_config_argv)/sizeof(*invalid_config_argv);
    bzero(&cfg, sizeof(cfg));
    ck_assert_int_eq(attestmgr_getopt(argc, invalid_config_argv, &cfg), -1);
}
END_TEST

int main(void)
{
    Suite *suite;
    SRunner *runner;
    TCase *test_cases;
    int nfail;

    suite = suite_create("am_getopt");
    test_cases = tcase_create("am_getopt");

    tcase_add_test(test_cases, test_attestmgr_getopt);
    tcase_add_test(test_cases, test_attestmgr_getopt_full_config_xml);
    tcase_add_test(test_cases, test_attestmgr_getopt_opts_trump_all);
    tcase_add_test(test_cases, test_attestmgr_getopt_env_trumps_config);
    tcase_add_test(test_cases, test_attestmgr_getopt_fail);

    suite_add_tcase(suite, test_cases);

    runner = srunner_create(suite);
    srunner_set_log(runner, "test_am_getopt.log");
    srunner_set_xml(runner, "test_am_getopt.xml");
    srunner_run_all(runner, CK_VERBOSE);
    nfail = srunner_ntests_failed(runner);
    if(runner) srunner_free(runner);
    return nfail;
}
