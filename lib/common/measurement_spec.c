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

/**
 * measurement_spec.c: Loading of measurement specification
 * metadata. Note that although measurement specs may not separate the
 * metadata from the actual spec, we're really just concerned with
 * getting the name and UUID here.
 */
#include <config.h>
#include <errno.h>
#include <stdlib.h>
#include "measurement_spec.h"

#include <string.h>
#include <dirent.h>

#include <util/xml_util.h>
#include <util/util.h>

#include <common/taint.h>

/*
 * Parses a given XML file to produce a pointer to the measurement specification
 * defined within.
 */
mspec_info *load_measurement_specification_info(const char *xmlfile)
{
    if(xmlfile == NULL)
        return NULL;
    xmlDoc *doc;
    xmlNode *root;
    xmlNode *tmp;
    int ret;
    mspec_info *meas_spec;
    char *rootname;

    dlog(6, "parsing file %s\n", xmlfile);
    /* FIXME: we should validate the document before untainting it! */
    doc = xmlReadFile(xmlfile, NULL, 0);
    if(doc == NULL) {
        return NULL;
    }
    root	= xmlDocGetRootElement(doc);
    rootname	= validate_cstring_ascii(root->name, SIZE_MAX);

    if(rootname == NULL) {
        dlog(2, "document is not a measurement_specification metafile\n");
        xmlFreeDoc(doc);
        return NULL;
    }

    if (strcasecmp(rootname, "measurement_specification") != 0) {
        dlog(2,"document %s is not a measurement_specification metafile\n", xmlfile);
        xmlFreeDoc(doc);
        return NULL;
    }


    meas_spec = (mspec_info  *)calloc(1, sizeof(mspec_info));
    if (!meas_spec) {
        dlog(1,"error allocating measurement_specification structure\n");
        xmlFreeDoc(doc);
        return NULL;
    }
    meas_spec->metadata_version = 0;
    char *version_str = xmlGetPropASCII(root, "version");
    if(version_str != NULL) {
        if(sscanf(version_str, "%hhu", &meas_spec->metadata_version) != 1) {
            dlog(1, "WARNING: parsing measurement spec metadata invalid version specified \"%s\""
                 " (defaulting to 0)\n", version_str);
        }
        free(version_str);
    }

    meas_spec->filename = strdup(xmlfile);
    for (tmp = root->children; tmp; tmp=tmp->next) {
        char *tmpname = validate_cstring_ascii(tmp->name, SIZE_MAX);

        if(tmp->type != XML_ELEMENT_NODE || tmpname == NULL) {
            continue;
        }
        if (strcasecmp(tmpname, "uuid") == 0) {
            char *uuidstr = xmlNodeGetContentASCII(tmp);
            if(uuidstr == NULL) {
                dperror("UUID node has no contents\n");
                uuid_clear(meas_spec->uuid);
                continue;
            }
            ret = uuid_parse(uuidstr, meas_spec->uuid);
            free(uuidstr);
            if (ret) {
                dperror("UUID did not parse, skipping\n");
                uuid_clear(meas_spec->uuid);
            }
            continue;
        }
        if (strcasecmp(tmpname, "name") == 0) {
            meas_spec->name = xmlNodeGetContentASCII(tmp);
        }

        if (strcasecmp(tmpname, "description") == 0) {
            meas_spec->desc = xmlNodeGetContentASCII(tmp);
        }
    }
    xmlFreeDoc(doc);

    if (meas_spec->name)
        dlog(2, "Registered mspec: %s\n", meas_spec->name);

    return meas_spec;

}


/*
 * Creates a pointer to a GList of measurement specifications by reading
 * XML specifications within a target directory.
 */
GList *load_all_measurement_specifications_info(const char *dirname)
{
    if(dirname==NULL)
        return NULL;
    struct dirent *dent;
    DIR *dir;
    GList *meas_specs = NULL;
    char scratch[256];

    dir = opendir(dirname);
    if (!dir) {
        dlog(0, "Error opening directory %s\n", dirname);
        return NULL;
    }
    for (dent = readdir(dir) ; dent; dent = readdir(dir)) {
        char *d_name     = UNTAINT(dent->d_name);
        char *xml_suffix = strstr(d_name, ".xml");
        if (xml_suffix && *(xml_suffix + 4) == '\0') {
            dlog(6, "Loading meas spec: %s\n", d_name);
            mspec_info *p;
            int rc;
            rc = snprintf(scratch, 256, "%s/%s", dirname, d_name);
            if(rc < 0 || rc >= 256) {
                dlog(3, "Error creating path string %s/%s?", dirname, d_name);
                continue;
            }

            p = load_measurement_specification_info(scratch);
            if (p)
                meas_specs = g_list_append(meas_specs, p);
        }
    }

    closedir(dir);
    return meas_specs;
}

mspec_info *find_measurement_specification_uuid(GList *measurement_specifications, uuid_t uuid)
{
    GList *l;
    if(!measurement_specifications || !uuid)
        return NULL;

    for (l = measurement_specifications; l && l->data; l = g_list_next(l)) {
        mspec_info *p = (mspec_info *)l->data;
        if (uuid_compare(p->uuid, uuid) == 0)
            return p;
    }
    return NULL;
}

void free_measurement_specification_info(mspec_info* ms)
{
    free(ms->name);
    free(ms->desc);
    free(ms->filename);
    free(ms);
}
