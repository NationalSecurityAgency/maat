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

/*
 * AM Service exec'd by the DBUS
 */

#include <stdlib.h>
#include <gio/gio.h>

#ifdef G_OS_UNIX
/* For STDOUT_FILENO */
#include <unistd.h>
#endif

#include <string.h>
#include <stdint.h>
#include <util/inet-socket.h>
#include <util/maat-io.h>
#include <util/xml_util.h>
#include "am.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <client/maat-client.h>


/* -------------------------------------------------------------------------- */

static GDBusNodeInfo *introspection_data = NULL;

/* Introspection data for the service we are exporting */
static const gchar introspection_xml[] =
    "<node>"
    "    <interface name='org.AttestationManager'>"
    "        <annotation name='org.AttestationManager.Annotation' value='OnInterface'/>"
    "        <annotation name='org.AttestationManager.Annotation' value='AlsoOnInterface'/>"
    "        <method name='startAttestation'>"
    "            <annotation name='org.AttestationManager.Annotation' value='OnMethod'/>"
    "            <arg type='s' name='resource' direction='in'/>"
    "            <arg type='s' name='response' direction='out'/>"
    "        </method>"
    "    </interface>"
    "</node>";

/* ------------------------------------------------------------------------ */

static char *parse_results(char *result, size_t size)
{
    /* The operations to be performed on this buffer do not regard the signedness
     * of the content */
    xmlDoc *doc = get_doc_from_blob((unsigned char *)result, size);
    if (doc == NULL)
        return "FAIL xml read";

    return xpath_get_content(doc, "/contract/result");
}

static void handle_method_call(GDBusConnection *connection,
                               const gchar *sender,
                               const gchar *object_path,
                               const gchar *interface_name,
                               const gchar *method_name,
                               GVariant    *parameters,
                               GDBusMethodInvocation *invocation,
                               gpointer    user_data)
{
    printf("Inside handle method call. method_name:  %s\n", method_name);
    struct addrinfo *targ_host = NULL;
    struct addrinfo *app_host = NULL;
    gchar *response = NULL;
    char *targ_host_addr, *app_host_addr;
    unsigned char *tmp;

    if ( g_strcmp0(method_name, "startAttestation") == 0) {
        const gchar *resource;
        g_variant_get(parameters, "(&s)", &resource);
        printf("Asked for initial contract with resource '%s'.\n", resource);

        int ret;
        size_t msglen = 0;
        size_t bytes_read = 0;

        char *targ_portnum = "2342";
        char *targ_host_name = "localhost";
        target_id_type_t target_type = TARGET_TYPE_HOST_PORT;
        char *app_host_name = "localhost";
        uint16_t app_portnum = 2342;
        char addrstr[100];

        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_flags |= AI_CANONNAME;

        // get addr for target
        ret = getaddrinfo(targ_host_name, NULL, &hints, &targ_host);
        if (ret != 0 || targ_host == NULL || targ_host->ai_addr == NULL) {
            printf("Error setting up target ip. getaddrinfo: %s\n", gai_strerror(ret));
            response = g_strdup("BAD");
            goto get_targ_addr_fail;
        }

        targ_host_addr = strdup(inet_ntop(targ_host->ai_family, (void *) &( (struct sockaddr_in *) targ_host->ai_addr)->sin_addr, addrstr, 100));
        if (targ_host_addr == NULL) {
            printf( "target host inet_ntop error\n");
            response = g_strdup("BAD");
            goto get_targ_addr_fail;
        }
        printf("measuring target: %s (%s)\n", targ_host_addr, targ_host->ai_canonname);

        // get addr for appraiser
        ret = getaddrinfo(app_host_name, NULL, &hints, &app_host);
        if (ret != 0 || app_host == NULL || app_host->ai_addr == NULL) {
            printf("Error getting addr for appraiser\n");
            response = g_strdup("BAD");
            goto get_app_addr_fail;
        }

        app_host_addr = strdup(inet_ntop(app_host->ai_family, (void *) &( (struct sockaddr_in *) app_host->ai_addr)->sin_addr, addrstr, 100));
        if (app_host_addr == NULL) {
            printf("Error setting up host addr\n");
            response = g_strdup("BAD");
            goto get_app_addr_fail;
        }
        printf("connecting to appraiser: %s : %hhu\n",app_host_addr, app_portnum);

        // connect to appraiser
        int appraiser_chan = connect_to_server(app_host_addr, app_portnum);

        if(appraiser_chan <= 0) {
            printf("error connecting to appraiser\n");
            response = g_strdup("BAD");
            goto connect_fail;
        }

        // send request
        ret = create_integrity_request(target_type,
                                       (xmlChar*)targ_host_addr,
                                       (xmlChar*)targ_portnum,
                                       (xmlChar*)resource,
                                       NULL,
                                       NULL,
                                       NULL,
                                       NULL,
                                       (xmlChar **)&tmp,
                                       &msglen);
        if(ret != 0) {
            printf("create_integrity_request failed: %d\n", ret);
            response = g_strdup("BAD");
            goto create_req_fail;
        }

        int iostatus;

        printf("sending request: %s\n", tmp);
        iostatus = maat_write_sz_buf(appraiser_chan, tmp, msglen, NULL, 2);
        if(iostatus != 0) {
            printf("Error sending request. returned status is %d: %s\n", iostatus,
                   strerror(-iostatus));
            response = g_strdup("BAD");
            goto cleanup;
        }

        char result[512];
        int eof_encountered = 0;
        // Function does not regards to signedness of the buffer
        iostatus = maat_read(appraiser_chan, (unsigned char *)result, 512, &bytes_read, &eof_encountered, 10);
        if(iostatus != 0) {
            printf("debug: %s\n", result);
            printf("Error reading response. returned status is %d: %s\n", iostatus,
                   strerror(-iostatus));
            response = g_strdup("BAD");
            goto cleanup;
        }

        if(eof_encountered != 0) {
            printf("Error: unexpected EOF encountered.");
            response = g_strdup("BAD");
            goto cleanup;
        }

        printf("Result from Appraiser: %s\n", result);
        response = g_strdup_printf("%s", parse_results(result, 512));
        goto cleanup;


    } else {
        printf("Unknown method: %s", method_name);
        //TODO: Is this the right error to return here? can't easily find a list of all G_DBUS_ERRORs
        g_dbus_method_invocation_return_error (invocation,
                                               G_DBUS_ERROR,
                                               G_DBUS_ERROR_MATCH_RULE_NOT_FOUND,
                                               "As requested, here's a GError that is registered (G_DBUS_ERROR_MATCH_RULE_NOT_FOUND)");
        goto exit;
    }

cleanup:
    free(tmp);
create_req_fail:
connect_fail:
    free(app_host_addr);
get_app_addr_fail:
    if(app_host != NULL) {
        freeaddrinfo(app_host);
    }
    free(targ_host_addr);
get_targ_addr_fail:
    if(targ_host != NULL) {
        freeaddrinfo(targ_host);
    }
    g_dbus_method_invocation_return_value(invocation, g_variant_new("(s)", response));
    g_free(response);
exit:
    return;
}

/* ------------------------------------------------------------------------------- */
/* Skipped handle_get_property and handle_set_property b/c didn't put these in xml */
/* ------------------------------------------------------------------------------- */

/* For now */ /* ??? */
static const GDBusInterfaceVTable interface_vtable = {
    handle_method_call,
    NULL,
    NULL,
    {NULL}
};

/* -------------------------------------------------------------------------------------------- */

static void on_bus_acquired(GDBusConnection *connection,
                            const gchar *name,
                            gpointer user_data)
{
    printf("\n Inside on_bus_acquired\n");
    guint registration_id;

    registration_id = g_dbus_connection_register_object(connection,
                      "/org/AttestationManager",
                      introspection_data->interfaces[0],
                      &interface_vtable,
                      NULL, /* user_data */
                      NULL, /* user_data_free_func */
                      NULL);/* GError** */
    g_assert(registration_id > 0);
}

static void on_name_acquired(GDBusConnection *connection,
                             const gchar *name,
                             gpointer user_data)
{
    printf("Acquired the name %s on the session bus\n", name);
}

static void on_name_lost(GDBusConnection *connection,
                         const gchar *name,
                         gpointer user_data)
{
    printf("Lost the name on the session bus\n");
    exit(1);
}

int main (int argc UNUSED, char **argv UNUSED)
{
    guint owner_id;
    GMainLoop *loop;
    printf("main()");
    //g_type_init();

    introspection_data = g_dbus_node_info_new_for_xml(introspection_xml, NULL);
    g_assert(introspection_data != NULL);

    owner_id = g_bus_own_name(G_BUS_TYPE_SESSION,
                              "org.AttestationManager",
                              G_BUS_NAME_OWNER_FLAGS_NONE,
                              on_bus_acquired,
                              on_name_acquired,
                              on_name_lost,
                              NULL,
                              NULL);

    printf("\n Owner id is %d", owner_id);
    loop = g_main_loop_new(NULL, FALSE);

    g_main_loop_run(loop);

    g_bus_unown_name(owner_id);

    g_dbus_node_info_unref(introspection_data);

    return 0;
}
