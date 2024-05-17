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

#define _LARGEFILE64_SOURCE

#include <errno.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

/*! \file
 * This ASP takes a process pid as input and finds all of its open files and
 * reads the elf library info.
 * The asp_measure function creates a node for each file found and attaches it
 * to the input node_id which should be the process node
 */

#define ASP_NAME "elf_reader"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <libelf.h>
#include <gelf.h>
#include <util/util.h>

#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <common/asp-errno.h>
#include <maat-basetypes.h>


typedef struct RefStruct {
    int refNum;
    char* file_name;
    char* ref_name;
} Reference;

/**
 * @brief This function frees a file references structure from memory.
 *
 * @param refs A double pointer to a file references structure.
 *
 * @param nr_refs A pointer to an unsigned long containing the number or references stored
 *                in the file references structure.
 *
 * @return This function does not return a value.
*/
static void free_reference_table(Reference **refs, size_t *nr_refs)
{
    size_t i = 0;
    for(i=0; i<*nr_refs; i++) {
        free((*refs)[i].file_name);
        free((*refs)[i].ref_name);
    }
    free(*refs);
    *refs = NULL;
    *nr_refs = 0;
}

/**
 * @brief This function computes the checksum of the content of a buffer.
 *
 * @param buf A pointer to the input buffer.
 *
 * @param buf_size The size of the input buffer.
 *
 * @param retbuf A double pointer to the return buffer containing the newly computed checksum.
 *
 * @param retsize A pointer to an unsigned long with the retbuf size value.
 *
 * @return 0 on success, otherwise an error value.
*/
static int compute_checksum_binary(uint8_t *buf, size_t bufsize,
                                   uint8_t **retbuf, size_t *retsize)
{
    GChecksum *csum = NULL;
    uint8_t *csumbuf = NULL;
    size_t csumsize = SHA256_TYPE_LEN;

    csumbuf = malloc(SHA256_TYPE_LEN);
    if (!csumbuf) {
        dperror("Error allocating checksum buffer\n");
        return -ENOMEM;
    }

    csum = g_checksum_new(G_CHECKSUM_SHA256);
    if (!csum) {
        free(csumbuf);
        dperror("Error getting sha256 checksum handle\n");
        return -1;
    }

    g_checksum_update(csum, buf, (gssize)bufsize);
    g_checksum_get_digest(csum, csumbuf, &csumsize);
    g_checksum_free(csum);

    *retbuf = csumbuf;
    *retsize = csumsize;

    return 0;
}

/**
 * @brief This function appends a new file reference into an existing file reference
 *        structure table.
 *
 * @param num The number of the file reference to be appended.
 *
 * @param file_name A pointer to the new file name to be appended.
 *
 * @param ref_name A pointer to the new reference name to be appended.
 *
 * @param refs A double pointer to the file references table to which the new reference
 *             in being appended to.
 *
 * @param nr_refs A pointer to an unsigned long with the number of entries in the file references
 *                table after append.
 *
 * @return 0 on success, otherwise an error value.
*/
static int append_reference(int num, char *file_name, char *ref_name,
                            Reference **refs, size_t *nr_refs)
{
    Reference *tmp = realloc(*refs, ((*nr_refs)+1)*sizeof(Reference));
    if(tmp == NULL) {
        return -ENOMEM;
    }

    *refs = tmp;

    tmp[*nr_refs].refNum = num;
    tmp[*nr_refs].file_name = strdup(file_name ? file_name : "(unknown)");
    tmp[*nr_refs].ref_name = strdup(ref_name);
    if(tmp[*nr_refs].file_name == NULL ||
            tmp[*nr_refs].ref_name == NULL) {
        free(tmp[*nr_refs].file_name);
        free(tmp[*nr_refs].ref_name);
        return -ENOMEM;
    }
    (*nr_refs)++;

    return 0;
}

/**
 * @brief This function appends an ELF symbol table entry into an existing ELF Header measurement
 *        data structure.
 *
 * @param data A pointer to the ELF Header measurement structure to which the new ELF symbol table
 *             entry will be appended to.
 *
 * @param sym A pointer to the new ELF symbol table entry that will be appended.
 *
 * @param symname A pointer to the new symbol name.
 *
 * @param ref A pointer to an existing file reference structure.
 *
 * @return 0 on success, otherwise an error value.
*/
static int append_symbol(elfheader_meas_data *data, GElf_Sym *sym, char *symname,
                         Reference *ref)
{
    elf_symbol *e = malloc(sizeof(elf_symbol));

    if(e == NULL) {
        return ENOMEM;
    }

    memcpy(&e->symbol, sym, sizeof(GElf_Sym));

    e->symbol_name = strdup(symname);
    e->file_name   = strdup(ref->file_name);
    e->ref_name    = strdup(ref->ref_name);
    e->version     = ref->refNum;

    if(e->symbol_name == NULL ||
            e->file_name   == NULL ||
            e->ref_name    == NULL) {
        free(e->symbol_name);
        free(e->file_name);
        free(e->ref_name);
        free(e);
        return ENOMEM;
    }

    data->symbols = g_list_append(data->symbols, e);
    return 0;
}

/**
 * @brief This function scans a verneed section of an ELF file and populates a file references
 *        structure with information from the vernaux structures.
 *
 * @param elf A pointer to an ELF file descriptor.
 *
 * @param refScn A pointer to an ELF file section descriptor.
 *
 * @param symbol_count An integer containing the symbol counter. This parameter is unused.
 *
 * @param elfheader_data A pointer to the ELF Header measurement structure to which the new ELF symbol table
 *                       entry will be appended to.
 *
 * @param refs A double pointer to an existing file references structure.
 *
 * @param nrrefs A pointer to an unsigned long with the number of entries in the file references
 *               table after append.
 *
 * @return 0 on success, otherwise an error value.
*/
static int scan_verneed_section(Elf *elf, Elf_Scn *refScn,
                                __attribute__((__unused__))int symbol_count,
                                elfheader_meas_data *elfheader_data,
                                Reference **refs, size_t *nrrefs)
{
    GElf_Shdr grefShdr;
    uint32_t i;
    uint64_t vna_offset	= 0;
    size_t vn_offset	= 0;
    Elf_Data *refData	= NULL;
    int ret_val;

    if (gelf_getshdr(refScn, &grefShdr) == NULL) {
        ret_val = elf_errno();
        asp_logerror("Error: failed to get referenced section header for VERNEED section: %s\n",
                     elf_errmsg(ret_val));
        goto error_out;
    }

    asp_logdebug("VERNEED section contains %d entries:\n",
                 grefShdr.sh_info);

    refData = elf_getdata(refScn, NULL);
    if (refData == NULL) {
        ret_val = elf_errno();
        asp_logerror("Error: failed to get data from VERNEED section: %s\n",
                     elf_errmsg(ret_val));
        goto error_out;
    }

    /*
     * Versym 0 is reserved for local symbols
     * Versym 1 is reserved for global symbols
     */
    if(append_reference(0, "local", "local", refs, nrrefs) != 0) {
        ret_val = ENOMEM;
        goto error_out;
    }

    if(append_reference(1, "global", "global", refs, nrrefs) != 0) {
        ret_val = ENOMEM;
        goto error_out;
    }

    /*
     * The verneed (version needed) section contains a linked list of
     * verneed structures. Each verneed structure points to a linked
     * list of vernaux (version needed auxilliary)
     * structures. Essentially, the verneed structure refers to a
     * library and the vernaux structures refer to the symbols being
     * imported. This isn't hard and fast. Version symbols are
     * retrofitted onto the ELF format. See
     * http://www.akkadia.org/drepper/symbol-versioning
     * for the best explanation I can find.
     *
     *   verneed
     * +---------+
     * | version | -- always 1
     * | count   | -- nr entries aux ents
     * | file    | -- index into strtab
     * |         |    for library name
     * | aux     | ----------------------->>+-------+
     * |         |                          | hash  | -- symbol hash
     * | next    | -- next verneed          | flags | -- ?
     * +---------+                          | other | -- index of this sym.
     *                                      |       |    referenced by
     *                                      |       |    .versym section
     *                                      | name  | -- index into strtab
     *                                      |       |    for symobl name
     *                                      | next  | -- next vernaux
     *                                      +-------+
     *
     * Our goal is to record all the vernaux structures so that we can
     * look up the vernaux entry for each imported symbol. The symbols
     * in the .dynsym section form a parallel array with entries in
     * the the versym section. The entries of versym have type syminfo
     * which is actually just a half word that matches "other" field
     * of the vernaux structure.
     *
     * Our (somewhat inelegant) solution is to just pack the vernaux
     * structures into an array (*refs) and then for each undefined
     * symbol, loop over the array until we find the vernaux entry
     * with the correct value of other. A better solution might be to
     * actually make the vernaux structures an array indexed by the
     * other field.
     */
    for(i = 0; i < grefShdr.sh_info; i++) {
        GElf_Verneed verneed_mem;
        GElf_Verneed *verneed = NULL;;
        char *filename = NULL;
        uint16_t j = 0;

        if(vn_offset > INT_MAX) {
            asp_logwarn("verneed structure offset too large\n");
            break;
        }

        verneed = gelf_getverneed(refData, (int)vn_offset, &verneed_mem);

        if (verneed == NULL) {
            asp_logwarn("Failed to get verneed structure %" PRIu32 "\n", i);
            break;
        }

        filename = elf_strptr(elf, grefShdr.sh_link, verneed->vn_file);
        if (filename == NULL) {
            asp_logwarn("Warning: verneed structure has no/invalid file name\n");
        } else {
            char * dependancyName = strdup(filename);
            if (dependancyName == NULL) {
                ret_val = errno;
                goto error_out;
            }
            elfheader_data->dependencies = g_list_append(elfheader_data->dependencies,
                                           dependancyName);
        }

        asp_logdebug("verneed structure %" PRIu32 " has %" PRIu16 " aux entries\n", i, verneed->vn_cnt);

        vna_offset = vn_offset + verneed->vn_aux;
        for (j = 0; j < verneed->vn_cnt; j++) {
            char *refname;
            GElf_Vernaux vernaux_mem;
            GElf_Vernaux *vernaux = gelf_getvernaux(refData, (int)vna_offset, &vernaux_mem);
            if(vernaux == NULL) {
                asp_logwarn("Warning: Failed to get vernaux structure (%" PRIu32 ",%" PRIu16")\n", i, j);
                break;
            }

            vna_offset += vernaux->vna_next;

            refname = elf_strptr(elf, grefShdr.sh_link, vernaux->vna_name);

            if(refname == NULL) {
                continue;
            }
            asp_logdebug("adding reference [%" PRIu16 "] for \"%s\" from lib %s\n",
                         vernaux->vna_other, refname, filename ? filename : "(unknown)");
            if(append_reference(vernaux->vna_other, filename, refname, refs, nrrefs) != 0) {
                asp_logerror("Failed to add reference \"[%" PRIu16 "] %s:%s\"\n",
                             vernaux->vna_other, filename ? filename : "(unknown)", refname);
                ret_val = ENOMEM;
                goto error_out;
            }

        }
        vn_offset += verneed->vn_next;
    }
    return 0;

error_out:
    asp_logerror("Scanning of GNU_verneed section failed\n");
    free_reference_table(refs, nrrefs);
    return ret_val;
}

/**
 * @brief This function appends file references and ELF symbols into an existing
 *        ELF Header measurement data structure.
 *
 * @param elf A pointer to an ELF file descriptor.
 *
 * @param symScn A pointer to an ELF file section descriptor.
 *
 * @param verScn A pointer to an ELF file section descriptor.
 *
 * @param symbol_count An unsigned long containing the symbol counter.
 *
 * @param refs A pointer to an existing file reference structure.
 *
 * @param refcount An unsigned long with the number of entries in the file reference structure.
 *
 * @param elfheader_data A pointer to an existing ELF Header measurement structure that will be populated.
 *
 * @return 0 on success, otherwise -1.
*/
static int zip_refs_and_symbols(Elf *elf,
                                Elf_Scn *symScn,
                                Elf_Scn *verScn,
                                size_t symbol_count,
                                Reference *refs,
                                size_t refcount,
                                elfheader_meas_data *elfheader_data)
{
    GElf_Shdr gsymShdr, gverShdr;
    Elf_Data *symData	= NULL;
    Elf_Data *verData	= NULL;

    if (gelf_getshdr(symScn, &gsymShdr) == NULL) {
        asp_logerror("zip_refs_and_symbols failed to get sym shdr\n");
        return -1;
    }

    symData = elf_getdata(symScn, NULL);
    if (symData == NULL) {
        asp_logerror("zip_refs_and_symbols failed to get sym data\n");
        return -1;
    }

    if (gelf_getshdr(verScn, &gverShdr) == NULL) {
        asp_logerror("zip_refs_and_symbols failed to get ver shdr\n");
        return -1;
    }
    verData = elf_getdata(verScn, NULL);
    if (verData == NULL) {
        asp_logerror("zip_refs_and_symbols failed to ver data\n");
        return -1;
    }

    int i = 0;

    for(i = 0; i < (int)symbol_count; i++) {
        GElf_Versym syminfo_mem, *syminfo;
        GElf_Sym sym;

        if (gelf_getsym(symData, i, &sym) == NULL) {
            asp_logerror("zip_refs_and_symbols failed to get sym %d\n", i);
            return -1;
        }

        char* symbolName = elf_strptr(elf, gsymShdr.sh_link, sym.st_name);
        if (symbolName == NULL) {
            continue;
        }


        // find matching reference/dependency for symbol

        if(sym.st_shndx == SHN_UNDEF) {
            syminfo = gelf_getversym(verData, i, &syminfo_mem);
            if (syminfo == NULL) {
                asp_logerror("zip_refs_and_symbols failed to get syminfo %d\n", i);
                // getversym failed with ELF_E_INVALID_INDEX
                return -1;
            }
            asp_logdebug("looking up vernaux for symbol %d: \"%s\" "
                         "(versym = %d)\n",
                         i, symbolName, syminfo_mem);
        } else {
            syminfo_mem = (sym.st_info & STB_LOCAL) ? 0 : 1 ;
        }

        int j = 0;
        int refIndex = 0;
        for (j = 0; j < (int)refcount; j++) {
            if (syminfo_mem == refs[j].refNum) {
                refIndex = j;
                break;
            }
        }
        if(j == (int)refcount) {
            asp_logwarn("zip_refs_and_symbols failed to match syminfo ref %d\n",
                        (int)syminfo_mem);
            return -1;
        }

        if(append_symbol(elfheader_data, &sym, symbolName, &refs[refIndex]) != 0) {
            asp_logerror("zip_refs_and_symbols failed to append symbols\n");
            return -1;
        }

    }
    return 0;
}


int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    int ret_val = 0;

    if( (ret_val = register_measurement_type(&elfheader_measurement_type)) )
        return ret_val;
    if( (ret_val = register_measurement_type(&filename_measurement_type)) )
        return ret_val;
    if( (ret_val = register_address_space(&file_addr_space)) )
        return ret_val;
    if( (ret_val = register_address_space(&simple_file_address_space)) )
        return ret_val;

    return ASP_APB_SUCCESS;
}

int asp_exit(int status UNUSED)
{
    return ASP_APB_SUCCESS;
}

/**
 * @brief This function hashes a program segment header content and adds the hash value into a node
 *        graph of type sha256_measurement_type.
 *
 * @param elf_path A pointer to an ELF file path.
 *
 * @param fd An integer value containing a file descriptor.
 *
 * @param phdr A pointer to a program segment header.
 *
 * @param g A pointer to a measurement graph.
 *
 * @param parent A node ID value.
 *
 * @return 0 on success, otherwise -1.
*/
static int hash_load_segment(char *elf_path, int fd, GElf_Phdr *phdr,
                             measurement_graph *g, node_id_t parent)
{
    measurement_variable mvar;
    measurement_data *meas_data;
    sha256_measurement_data *hash_data = NULL;
    node_id_t child = INVALID_NODE_ID;
    marshalled_data *md = NULL;
    int rc;
    size_t mapsz = phdr->p_memsz;

    mapsz += 0x1000 - (mapsz % 0x1000);
    char *buf = calloc(1, mapsz);

    if(buf == NULL) {
        goto error_alloc_buf;
    }
    if(lseek64(fd, (off_t)phdr->p_offset, SEEK_SET) != 0) {
        goto error_lseek;
    }

    if(read(fd, buf, phdr->p_filesz) != (int)phdr->p_filesz) {
        goto error_read;
    }
    asp_loginfo("hashing region of size %"PRIx64" of file padded to %"PRIx64"\n",
                phdr->p_filesz, mapsz);
    mvar.type    = &elf_section_target_type;
    mvar.address = alloc_address(&file_region_address_space);
    if(mvar.address == NULL) {
        asp_logerror("failed to alloc address\n");
        goto error_alloc_address;
    }

    if(file_region_address_set_path(mvar.address, elf_path) != 0 ||
            file_region_address_set_offset(mvar.address, (off_t)phdr->p_offset) != 0 ||
            file_region_address_set_size(mvar.address, phdr->p_filesz) != 0) {
        asp_logerror("failed to setup address\n");
        goto error_set_address;
    }

    if((meas_data = alloc_measurement_data(&sha256_measurement_type)) == NULL) {
        asp_logerror("failed to allocate measurement data\n");
        goto error_alloc_measurement;
    }

    hash_data = container_of(meas_data, typeof(*hash_data), meas_data);

    uint8_t *hbuf;
    size_t hbuf_size;

    if (compute_checksum_binary((unsigned char *)buf, mapsz, &hbuf, &hbuf_size) < 0) {
        asp_logerror("failed to allocate/compute sha256 checksum\n");
        goto error_alloc_measurement;
    }
    memcpy(hash_data->sha256_hash, hbuf, SHA256_TYPE_LEN);
    free(hbuf);

    md = marshall_measurement_data(&hash_data->meas_data);
    if(md == NULL) {
        asp_logerror("failed to marshall hash data\n");
        goto error_marshall_data;
    }
    if((rc = measurement_graph_add_node(g, &mvar, md, &child)) < 0) {
        asp_logerror("failed to add measurement node: %d\n", rc);
        goto error_add_node;
    }

    edge_id_t e;
    if(measurement_graph_add_edge(g, parent, "segment", child, &e) < 0) {
        asp_logerror("failed to add measurement edge\n");
        goto error_add_edge;
    }

    free(buf);
    free_measurement_data(&hash_data->meas_data);
    free_measurement_data(&md->meas_data);
    free_address(mvar.address);
    return 0;

error_add_edge:
error_add_node:
    free_measurement_data(&md->meas_data);
error_marshall_data:
    free_measurement_data(&hash_data->meas_data);
error_alloc_measurement:
error_set_address:
    free_address(mvar.address);
error_alloc_address:
error_read:
error_lseek:
    free(buf);
error_alloc_buf:
    return -1;
}

/**
 * @brief This function hashes a section header content and adds the hash value into a node
 *        graph of type sha256_measurement_type.
 *
 * @param elf_path A pointer to an ELF file path.
 *
 * @param xhdr A pointer to a section header structure, including the section name.
 *
 * @param scn A pointer to an ELF file section descriptor.
 *
 * @param g A pointer to a measurement graph.
 *
 * @param parent A node ID value.
 *
 * @return 0 on success, otherwise -1.
*/
static int hash_section(char *elf_path, elf_sct_hdr *xhdr, Elf_Scn *scn,
                        measurement_graph *g, node_id_t parent)
{
    Elf_Data *data;
    measurement_variable mvar;
    measurement_data *meas_data;
    sha256_measurement_data *hash_data = NULL;
    node_id_t child = INVALID_NODE_ID;
    marshalled_data *md = NULL;
    GElf_Shdr *hdr = &xhdr->section_hdr;
    int rc;

    if((data = elf_rawdata(scn, NULL)) == NULL) {
        asp_logerror("failed to get rawdata for section\n");
        goto error_rawdata;
    }

    mvar.type    = &elf_section_target_type;
    mvar.address = alloc_address(&file_region_address_space);
    if(mvar.address == NULL) {
        asp_logerror("failed to alloc address\n");
        goto error_alloc_address;
    }

    if(file_region_address_set_path(mvar.address, elf_path) != 0 ||
            file_region_address_set_offset(mvar.address, (off_t)hdr->sh_offset) != 0 ||
            file_region_address_set_size(mvar.address, hdr->sh_size) != 0) {
        asp_logerror("failed to setup address\n");
        goto error_set_address;
    }

    if((meas_data = alloc_measurement_data(&sha256_measurement_type)) == NULL) {
        asp_logerror("failed to allocate measurement data\n");
        goto error_alloc_measurement;
    }

    hash_data = container_of(meas_data, typeof(*hash_data), meas_data);

    uint8_t *hbuf;
    size_t hbuf_size;

    if (compute_checksum_binary(data->d_buf, data->d_size,
                                &hbuf, &hbuf_size) < 0) {
        asp_logerror("failed to allocate/compute sha256 checksum\n");
        goto error_alloc_measurement;
    }
    memcpy(hash_data->sha256_hash, hbuf, SHA256_TYPE_LEN);
    free(hbuf);

    md = marshall_measurement_data(&hash_data->meas_data);
    if(md == NULL) {
        asp_logerror("failed to marshall hash data\n");
        goto error_marshall_data;
    }
    if((rc = measurement_graph_add_node(g, &mvar, md, &child)) < 0) {
        asp_logerror("failed to add measurement node: %d\n", rc);
        goto error_add_node;
    }

    edge_id_t e;
    if(measurement_graph_add_edge(g, parent, "section"/* xhdr->section_name */, child, &e) < 0) {
        asp_logerror("failed to add measurement edge\n");
        goto error_add_edge;
    }

    free_measurement_data(&hash_data->meas_data);
    free_measurement_data(&md->meas_data);
    free_address(mvar.address);
    return 0;

error_add_edge:
error_add_node:
    free_measurement_data(&md->meas_data);
error_marshall_data:
    free_measurement_data(&hash_data->meas_data);
error_alloc_measurement:
error_set_address:
    free_address(mvar.address);
error_alloc_address:
error_rawdata:
    return -1;
}

int asp_measure(int argc, char *argv[])
{
    address *address			= NULL;
    char *path				= NULL;
    int fd				= -1;
    node_id_t node_id			= INVALID_NODE_ID;
    measurement_graph *graph		= NULL;
    int ret_val				= 0;
    measurement_data *meas_data		= NULL;
    elfheader_meas_data *elfheader_data = NULL;

    Elf * elf		= NULL;
    Elf_Scn *scn	= NULL;
    Elf_Scn *symScn	= NULL;
    Elf_Scn *verScn	= NULL;
    GElf_Shdr gshdr;
    size_t shstrndx;

    Reference *refs = NULL;
    size_t refcount = 0;

    if ((argc < 3) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        ret_val = EINVAL;
        goto error_bad_args;
    }


    meas_data = alloc_measurement_data(&elfheader_measurement_type);
    if(meas_data == NULL) {
        asp_logerror("Error: failed to allocate elfheader measurement data");
        ret_val = ENOMEM;
        goto error_alloc_data;
    }
    elfheader_data = container_of(meas_data, elfheader_meas_data, d);

    /* Extract the file address from the passed in node */
    address = measurement_node_get_address(graph, node_id);
    if (address == NULL) {
        asp_logerror("failed to get node address: %d\n", ret_val);
        ret_val = EINVAL;
        goto error_get_address;
    }

    if(address->space == &file_addr_space) {
        path = ((file_addr*)address)->fullpath_file_name;
    } else if(address->space == &simple_file_address_space) {
        path = ((simple_file_address *)address)->filename;
    }
    if(path == NULL) {
        asp_logerror("Error: argument must have a path-like address (given a \"%s\"\n",
                     address->space->name);
        ret_val = EINVAL;
        goto error_no_path;
    }

    asp_logdebug("elfheaderasp: measuring ELF file @ \"%s\"\n", path);

    fd = open(path, O_RDONLY);
    if(fd < 0) {
        asp_logerror("failed to open file %s for elf header parsing\n", path);
        ret_val = errno;
        goto error_open_file;
    }

    elf_version(EV_CURRENT);
    elf=elf_begin(fd, ELF_C_READ,NULL);
    if(elf == NULL) {
        ret_val = 0;
        goto not_an_elf;
    }

    elfheader_data->filename = strdup(path);
    if (elfheader_data->filename == NULL) {
        ret_val = errno;
        asp_logerror("failed to copy filename \"%s\"\n", path);
        goto error_elf_file_name;
    }

    if (gelf_getehdr(elf, &elfheader_data->elf_header) == NULL) {
        ret_val = 0; // elf_errno();
        // asp_logerror("failed to get elf header: %s (file = \"%s\")\n", elf_errmsg(ret_val), path);
        goto error_no_elf_file_header;
    }

    size_t nr_phdrs;
    if(elf_getphdrnum(elf, &nr_phdrs) < 0) {
        ret_val = elf_errno();
        asp_logerror("Failed to get program header count: %s\n", elf_errmsg(ret_val));
        goto error_getphdrnum;
    } else if(nr_phdrs > INT_MAX) {
        ret_val = EINVAL;
        asp_logerror("Invalid program header count %zd\n", nr_phdrs);
        goto error_getphdrnum;
    }

    elfheader_data->nr_phdrs = nr_phdrs;
    elfheader_data->program_headers = calloc(nr_phdrs, sizeof(GElf_Phdr));
    if(elfheader_data->program_headers == NULL) {
        ret_val = errno;
        asp_logerror("Unable to allocate memory for program headers: %s\n",
                     strerror(ret_val));
        goto error_alloc_phdrs;
    }

    int i = 0;
    for(i = 0; i < (int)nr_phdrs; i++) {
        GElf_Phdr *phdr = &elfheader_data->program_headers[i];
        if(gelf_getphdr(elf, i, phdr) == NULL) {
            ret_val = elf_errno();
            asp_logerror("failed to get elf program header [%d]: %s\n",
                         i, elf_errmsg(ret_val));
        }
        if((phdr->p_type == PT_LOAD) && !(phdr->p_flags & PF_W)) {
            hash_load_segment(path, fd, phdr, graph, node_id);
        }
    }

    // now read elf sections
    size_t sectionHdrTblLoc;
    if (elf_getshdrnum(elf, &sectionHdrTblLoc) == -1) {
        ret_val = elf_errno();
        asp_logerror("failed to get count of elf section headers: %s\n", elf_errmsg(ret_val));
        goto error_unknown_section_numbers;
    }

    scn = NULL;

    if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
        ret_val = elf_errno();
        asp_logerror(" elf_getshdrstrndx() failed : %s.\n", elf_errmsg(ret_val));
        goto error_unknown_section_index;
    }

    int symbol_count = 0;

    char *sectName = NULL;
    elf_sct_hdr *elfSectHdr = NULL;
    int scanned_verneed = 0;
    Elf64_Word symStrTabNum;
    // Scan through all the header sections,
    // and append each section header to list of section headers
    while ((scn = elf_nextscn(elf, scn)) != NULL ) {
        elfSectHdr = malloc(sizeof(elf_sct_hdr));
        if (elfSectHdr == NULL) {
            ret_val = errno;
            asp_logerror("Failed to allocate buffer for section header");
            goto error_scanning_section_hdrs;
        }
        if (gelf_getshdr(scn, &gshdr) == NULL) {
            ret_val = elf_errno();
            asp_logerror("Failed to get elf section header\n");
            goto error_scanning_section_hdrs;
        }


        memcpy(&elfSectHdr->section_hdr, &gshdr, sizeof(GElf_Shdr));

        sectName = elf_strptr(elf, shstrndx, gshdr.sh_name);
        if((elfSectHdr->section_name = strdup(sectName)) == NULL) {
            asp_logerror("Failed to copy section name \"%s\"", sectName);
            ret_val = ENOMEM;
            goto error_scanning_section_hdrs;
        }

        asp_logdebug("[%d] Section Header Name = %s\n", elfSectHdr->section_hdr.sh_name,
                     elfSectHdr->section_name);

        elfheader_data->section_headers = g_list_append(elfheader_data->section_headers,
                                          elfSectHdr);

        if((gshdr.sh_type != SHT_NOBITS) &&
                ((gshdr.sh_flags & SHF_ALLOC) != 0) &&
                ((gshdr.sh_flags & SHF_WRITE) == 0)) {
            if(hash_section(elfheader_data->filename, elfSectHdr, scn, graph, node_id) != 0) {
                asp_logwarn("Warning: failed to hash ELF file section \"%s\"\n",
                            elfSectHdr->section_name);
            }
        }

        elfSectHdr = NULL;


        // store symbol/version/reference headers to process symbol information
        if (gshdr.sh_type == SHT_DYNSYM) {
            if(symScn != NULL) {
                asp_logerror("Duplicate Symbol sections found.\n");
                ret_val = EINVAL;
                goto error_scanning_section_hdrs;
            }
            symbol_count = (int)(gshdr.sh_size / gshdr.sh_entsize);
            symScn = scn;
            asp_loginfo("dynsym section %"PRIu64", strtab %" PRIu32 "\n", elf_ndxscn(symScn), gshdr.sh_link);
            symStrTabNum = gshdr.sh_link;
        }

        if (gshdr.sh_type == SHT_GNU_versym ) {
            if(verScn != NULL) {
                asp_logerror("Duplicate versym sections found.\n");
                ret_val = EINVAL;
                goto error_scanning_section_hdrs;
            }
            if(gshdr.sh_link != elf_ndxscn(symScn)) {
                asp_logwarn("Versym section link != DYNSYM section\n");
            }
            verScn = scn;
        }

        if (gshdr.sh_type == SHT_GNU_verneed) {
            if(scanned_verneed != 0) {
                asp_logerror("Duplicate GNU_verneed sections found.\n");
                ret_val = EINVAL;
                goto error_scanning_section_hdrs;
            }
            if(symScn == NULL) {
                ret_val = EINVAL;
                asp_logerror("Found GNU_verneed section before SYMTAB or DYNSYM section\n");
                goto error_scanning_section_hdrs;
            }
            if(gshdr.sh_link != symStrTabNum) {
                asp_logwarn("Verneed link (%" PRIu32 ") != symStrTab (%" PRIu32 ")\n",
                            gshdr.sh_link, symStrTabNum);
            }

            if((ret_val = scan_verneed_section(elf, scn, symbol_count,
                                               elfheader_data, &refs,
                                               &refcount)) != 0) {
                asp_logerror("Failed to scan verneed section\n");
                goto error_scanning_section_hdrs;
            }
            asp_logdebug("Done scanning verneed section (refcount == %zd)\n", refcount);
            scanned_verneed = 1;
        }
    }

    if(scanned_verneed == 0) {
        asp_logwarn("No GNU_verneed section found in file \"%s\".\n", elfheader_data->filename);
    } else {
        if((ret_val = zip_refs_and_symbols(elf, symScn, verScn, (size_t)symbol_count,
                                           refs, refcount, elfheader_data)) != 0) {
            asp_logerror("Failed to zip refs and symbols\n");
            goto error_zip_refs;
        }
    }

    asp_logdebug("Adding measurement of type "MAGIC_FMT" to node "ID_FMT"\n",
                 elfheader_data->d.type->magic, node_id);

    ret_val = measurement_node_add_rawdata(graph, node_id,  &elfheader_data->d);

    dlog(6, "ELF NODE "ID_FMT" with data of type "MAGIC_FMT"\n", node_id, elfheader_data->d.type->magic);

error_zip_refs:
// ERROR Handling Cases
error_scanning_section_hdrs:
    free_reference_table(&refs, &refcount);
    free(elfSectHdr);

error_unknown_section_index:
error_unknown_section_numbers:
error_alloc_phdrs:
error_getphdrnum:
error_no_elf_file_header:

error_elf_file_name:
    elf_end(elf);

not_an_elf:
    if (fd >= 0) {
        close(fd);
    }
error_open_file:

error_no_path:
    free_address(address);
error_get_address:
    free_measurement_data(&elfheader_data->d);
error_alloc_data:
    unmap_measurement_graph(graph);
error_bad_args:
    return ret_val;
}
