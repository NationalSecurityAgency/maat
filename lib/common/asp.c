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
#include <stdio.h>
#include <string.h>
#include <uuid/uuid.h>
#include <glib.h>
#include <dlfcn.h>
#include <dirent.h>
#include <util/util.h>
#include <util/keyvalue.h>
#include <util/xml_util.h>
#include <uuid/uuid.h>

#include <common/taint.h>
#include <common/asp_info.h>

#include <common/asp.h>

#ifdef ENABLE_SELINUX
#include <selinux/selinux.h>
#endif

struct asp *load_asp_info(const char *xmlfile)
{
    xmlDoc *doc;
    xmlNode *root;
    xmlNode *tmp;
    int ret;
    struct asp *asp;
    char *rootname, *unstripped, *stripped;

    if(xmlfile == NULL) {
        return NULL;
    }

    dlog(6, "Parsing file %s\n", xmlfile);

    /* FIXME: we should validate the document before untainting it! */
    doc = UNTAINT(xmlReadFile(xmlfile, NULL, 0));
    if(doc == NULL) {
        return NULL;
    }
    root     = xmlDocGetRootElement(doc);
    rootname = validate_cstring_ascii(root->name, SIZE_MAX);

    if (rootname == NULL || strcasecmp(rootname, "asp") != 0) {
        dlog(0, "ERROR: Document %s is not an ASP metafile\n", xmlfile);
        xmlFreeDoc(doc);
        return NULL;
    }

    asp = (struct asp *)malloc(sizeof(struct asp));
    if (!asp) {
        dlog(0, "Error allocating asp structure\n");
        xmlFreeDoc(doc);
        return NULL;
    }
    memset(asp, 0, sizeof(struct asp));
    asp->filename = strdup(xmlfile);

    asp->metadata_version = 0;
    char *version_str = xmlGetPropASCII(root, "version");
    if(version_str != NULL) {
        if(sscanf(version_str, "%hhu", &asp->metadata_version) != 1) {
            dlog(1, "WARNING: parsing ASP metadata invalid version specified \"%s\""
                 " (defaulting to 0)\n", version_str);
        }
        free(version_str);
    }

    for (tmp = root->children; tmp; tmp=tmp->next) {
        char *tmpname = validate_cstring_ascii(tmp->name, SIZE_MAX);

        if((tmp->type != XML_ELEMENT_NODE) || tmpname == NULL) {
            continue;
        }

        if (strcasecmp(tmpname, "name") == 0) {
            unstripped = xmlNodeGetContentASCII(tmp);

            ret = strip_whitespace(unstripped, &stripped);
            free(unstripped);
            if (ret) {
                dlog(2, "Unable to strip whitespace from ASP name\n");
                continue;
            }

            asp->name = stripped;
        }

        if (strcasecmp(tmpname, "description") == 0) {
            unstripped = xmlNodeGetContentASCII(tmp);

            ret = strip_whitespace(unstripped, &stripped);
            free(unstripped);
            if (ret) {
                dlog(2, "Unable to strip whitespace from ASP description");
                continue;
            }

            asp->desc = stripped;
        }

        if (strcasecmp(tmpname, "aspfile") == 0) {
            if(asp->file != NULL)
                continue;

            asp->file = xml_parse_file(tmp);
        }

        if (strcasecmp(tmpname, "uuid") == 0) {
            unstripped = xmlNodeGetContentASCII(tmp);

            ret = strip_whitespace(unstripped, &stripped);
            free(unstripped);
            if (ret) {
                dlog(2, "Unable to strip whitespace from UUID entry\n");
                uuid_clear(asp->uuid);
                continue;
            }

            ret = uuid_parse(stripped, asp->uuid);
            free(stripped);
            if (ret) {
                dlog(0, "UUID did not parse, skipping\n");
                uuid_clear(asp->uuid);
            }
            continue;
        }

        if (strcasecmp(tmpname, "measurers") == 0) {
            // TODO: update parse_measurers() function for capabilities
            //            parse_measurers(asp, tmp);
            continue;
        }

        if (strcasecmp(tmpname, "security_context") == 0) {
            parse_exe_sec_ctxt(&asp->desired_sec_ctxt, tmp);
            continue;
        }
    }
    xmlFreeDoc(doc);

    if(asp->name == NULL) {
        dlog(4, "Registering ASP: (Null)\n");
    } else {
        dlog(4, "Registering ASP: %s\n", asp->name);
    }
    return asp;

}


/**
 * Gathers the info of each asp available on the system and loads it
 * into a GList to return
 */
GList *load_all_asps_info(const char *dirname)
{
    if(dirname==NULL)
        return NULL;
    struct dirent *dent;
    DIR *dir;
    GList *asps = NULL;
    char scratch[256];

    dir = opendir(dirname);
    if (!dir) {
        dlog(0, "Error opening directory %s\n", dirname);
        return NULL;
    }
    for (dent = readdir(dir) ; dent; dent = readdir(dir)) {
        char *xml_suffix = strstr(dent->d_name, ".xml");
        if (xml_suffix && *(xml_suffix + 4) == '\0') {
            struct asp *p;
            int rc;
            rc = snprintf(scratch, 256, "%s/%s", dirname, dent->d_name);
            if(rc < 0 || rc >= 256) {
                dlog(0, "Error creating path string %s/%s?", dirname, dent->d_name);
                continue;
            }

            p = load_asp_info(scratch);
            if (p)
                asps = g_list_append(asps, p);
        }
    }

    closedir(dir);
    return asps;
}

/*
 * Walk the list of asps and free each element, followed by the list.
 */
void unload_all_asps(GList *asps)
{
    g_list_foreach(asps, (GFunc)&free_asp, NULL);
    g_list_free(asps);
    return;
}

/**
 * Finds the uuid of an asp, given its name. Returns Null if no match is found
 */
struct asp *find_asp(GList *list, const char *name)
{
    GList *l;
    if(!list || !name)
        return NULL;

    for (l = list; l && l->data; l = g_list_next(l)) {
        struct asp *p = (struct asp *)l->data;

        if (strcasecmp(p->name, name)==0) {
            return p;
        }
    }
    return NULL;
}

/**
 * Searches @asps (GList of struct asp*) to find all of the
 * ASPs named in @names (GList of char*)
 *
 * Returns a GList of the selected asps (GList of struct asp*)
 */
GList *find_asps(GList *asps, GList *names)
{
    GList *out = NULL;
    GList *iter = NULL;

    for(iter = g_list_first(names); iter && iter->data; iter = g_list_next(iter)) {
        char *name = (char *)iter->data;

        struct asp *asp = find_asp(asps, name);

        if(asp) {
            out = g_list_append(out, asp);
        }
    }

    return out;
}



/**
 * Given a list of asps, returns the first asp whose uuid matches the given uuid
 */
struct asp *find_asp_uuid(GList *asps, uuid_t uuid)
{
    GList *l;
    if(!asps || !uuid)
        return NULL;

    for (l = asps; l && l->data; l = g_list_next(l)) {
        struct asp *p = (struct asp *)l->data;

        if (uuid_compare(p->uuid, uuid) == 0)
            return p;
    }
    return NULL;
}

#ifdef TEST
int main(void)
{
    GList *asps;

    LIBXML_TEST_VERSION;

    asps = load_all_asps_info("./asps");


    printf("Registered %d asps\n", g_list_length(asps));

    printf("unloading..\n");
    unload_all_asps(asps);

    xmlCleanupParser();
}
#endif

/* Local Variables:  */
/* mode: c           */
/* c-basic-offset: 4 */
/* End:              */
