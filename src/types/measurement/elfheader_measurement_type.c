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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <util/base64.h>
#include <util/util.h>
#include <elfheader_measurement_type.h>
#include <tpl.h>

static measurement_data *elfheader_type_alloc_data(void)
{
    elfheader_meas_data *ret;
    ret = (elfheader_meas_data *)malloc(sizeof(*ret));
    if (!ret) {
        return NULL;
    }
    bzero(ret, sizeof(elfheader_meas_data));
    ret->d.type = &elfheader_measurement_type;
    return (measurement_data *)ret;
}

static measurement_data *copy_elfheader_measurement_data(measurement_data *d)
{
    if(d == NULL) {
        return NULL;
    }
    elfheader_meas_data *elfdata = (elfheader_meas_data *)d;
    elfheader_meas_data *ret = (typeof(ret))alloc_measurement_data(&elfheader_measurement_type);
    elf_sct_hdr * elfSecHdr = NULL;
    elf_symbol * elfSym = NULL;

    if (!ret) {
        return NULL;
    }

    memcpy(&ret->elf_header, &elfdata->elf_header, sizeof(GElf_Ehdr));

    ret->program_headers = calloc(elfdata->nr_phdrs, sizeof(GElf_Phdr));
    if(ret->program_headers == NULL) {
        goto error_alloc_phdrs;
    }
    memcpy(ret->program_headers, elfdata->program_headers,
           elfdata->nr_phdrs*sizeof(GElf_Phdr));
    GList *iter;
    for (iter = g_list_first(elfdata->section_headers); iter != NULL; iter = g_list_next(iter)) {
        elf_sct_hdr *orgSecHdr = (elf_sct_hdr *)iter->data;
        elfSecHdr = malloc(sizeof(elf_sct_hdr));
        if (elfSecHdr == NULL) {
            goto memerror_elfSecHdr;
        }
        elfSecHdr->section_name = strdup(orgSecHdr->section_name);
        if (elfSecHdr->section_name == NULL) {
            goto memerror_sectionName;
        }
        elfSecHdr->section_hdr.sh_name = orgSecHdr->section_hdr.sh_name;
        elfSecHdr->section_hdr.sh_type = orgSecHdr->section_hdr.sh_type;
        elfSecHdr->section_hdr.sh_flags = orgSecHdr->section_hdr.sh_flags;
        elfSecHdr->section_hdr.sh_offset = orgSecHdr->section_hdr.sh_offset;
        elfSecHdr->section_hdr.sh_size = orgSecHdr->section_hdr.sh_size;
        elfSecHdr->section_hdr.sh_link = orgSecHdr->section_hdr.sh_link;
        elfSecHdr->section_hdr.sh_info = orgSecHdr->section_hdr.sh_info;
        elfSecHdr->section_hdr.sh_addralign = orgSecHdr->section_hdr.sh_addralign;
        elfSecHdr->section_hdr.sh_entsize = orgSecHdr->section_hdr.sh_entsize;

        ret->section_headers = g_list_append(ret->section_headers, elfSecHdr);
        elfSecHdr = NULL;
    }

    for (iter = g_list_first(elfdata->symbols); iter != NULL; iter = g_list_next(iter)) {
        elf_symbol *orgSym = (elf_symbol *)iter->data;
        elfSym = malloc(sizeof(elf_symbol));
        if (elfSym == NULL) {
            goto memerror_elfsym;
        }
        elfSym->symbol_name	= strdup(orgSym->symbol_name);
        elfSym->file_name	= strdup(orgSym->file_name);
        elfSym->ref_name	= strdup(orgSym->ref_name);

        if (elfSym->symbol_name == NULL ||
                elfSym->file_name == NULL ||
                elfSym->ref_name == NULL) {
            goto memerror_symnames;
        }

        elfSym->version = orgSym->version;
        elfSym->symbol.st_name	= orgSym->symbol.st_name;
        elfSym->symbol.st_info	= orgSym->symbol.st_info;
        elfSym->symbol.st_other = orgSym->symbol.st_other;
        elfSym->symbol.st_shndx = orgSym->symbol.st_shndx;
        elfSym->symbol.st_value = orgSym->symbol.st_value;
        elfSym->symbol.st_size	= orgSym->symbol.st_size;

        ret->symbols = g_list_append(ret->symbols, elfSym);
        elfSym = NULL;
    }

    for (iter = g_list_first(elfdata->dependencies); iter != NULL; iter = g_list_next(iter)) {

        char * orgDependency = (char *) iter->data;
        char * elfDependency = strdup(orgDependency);
        if (elfDependency == NULL) {
            goto memerror_depends;
        }
        ret->dependencies = g_list_append(ret->dependencies, elfDependency);
        elfDependency = NULL;
    }

    return (measurement_data *)ret;

memerror_depends:
memerror_symnames:
    if (elfSym != NULL) {
        free(elfSym->symbol_name);
        free(elfSym->file_name);
        free(elfSym->ref_name);
    }
    free(elfSym);
memerror_elfsym:
    if (elfSecHdr != NULL) {
        free(elfSecHdr->section_name);
    }
memerror_sectionName:
    free(elfSecHdr);
memerror_elfSecHdr:
error_alloc_phdrs:
    free_measurement_data(&ret->d);
    dlog(0, "Insufficient Memory Available\n");
    return NULL;
}

static void free_elf_sect_hdr(elf_sct_hdr *hdr)
{
    if(hdr != NULL) {
        free(hdr->section_name);
        free(hdr);
    }
}

static void free_elf_dependencies(char *dep)
{
    free(dep);
}

static void free_elf_symbols(elf_symbol * sym)
{
    if(sym != NULL) {
        free(sym->symbol_name);
        free(sym->file_name);
        free(sym->ref_name);
        free(sym);
    }
}

static void elfheader_type_free_data(measurement_data *d)
{
    if(d != NULL) {
        elfheader_meas_data *elfdata = container_of(d, elfheader_meas_data, d);

        free(elfdata->filename);
        free(elfdata->program_headers);
        g_list_free_full(elfdata->section_headers, (GDestroyNotify)free_elf_sect_hdr);
        g_list_free_full(elfdata->symbols, (GDestroyNotify)free_elf_symbols);
        g_list_free_full(elfdata->dependencies, (GDestroyNotify)free_elf_dependencies);
        free(elfdata);
    }
}

static int elfheader_type_serialize_data(measurement_data *d, char **serial_data,
        size_t *serial_data_size)
{
    if(d == NULL) {
        return -EINVAL;
    }

    elfheader_meas_data *elfdata = (elfheader_meas_data *)d;
    void *tplbuf = NULL;
    size_t tplsize = 0;
    char *b64 = NULL;
    GList *iter = NULL;
    tpl_node *tn = NULL;

    char * sectName = NULL;
    uint32_t sh_name, sh_type, sh_link, sh_info;
    uint64_t sh_flags, sh_addr, sh_offset;
    uint64_t sh_size, sh_addralign, sh_entsize;
    char * symbolName;
    char * fileName;
    char * refName;
    int version;
    int symlength, reflength, filelength;
    uint64_t st_name, st_shndx, st_value, st_size;
    char st_info, st_other;
    char * dependName = NULL;
    GElf_Phdr phdr = {0};
    elf_sct_hdr shdr = {0};
    elf_symbol sym = {0};

    if (elfdata->filename == NULL) {
        dlog(0, "No Filename Present, Can't Serialize Data\n");
        goto err_no_filename;
    }

    tn = tpl_map("sc#vvuUUUuvvvvvv"  /* ELF header info */
                 "A(uuUUUUUU)"       /* Program headers */
                 "A(suuUUUUuuUU)"    /* Section headers */
                 "A(sssiUccUUU)"     /* Symbols */
                 "A(s)",             /* Dependencies */
                 &elfdata->filename,
                 elfdata->elf_header.e_ident, 16,
                 &elfdata->elf_header.e_type,
                 &elfdata->elf_header.e_machine,
                 &elfdata->elf_header.e_version,
                 &elfdata->elf_header.e_entry,
                 &elfdata->elf_header.e_phoff,
                 &elfdata->elf_header.e_shoff,
                 &elfdata->elf_header.e_flags,
                 &elfdata->elf_header.e_ehsize,
                 &elfdata->elf_header.e_phentsize,
                 &elfdata->elf_header.e_phnum,
                 &elfdata->elf_header.e_shentsize,
                 &elfdata->elf_header.e_shnum,
                 &elfdata->elf_header.e_shstrndx,

                 &phdr.p_type,
                 &phdr.p_flags,
                 &phdr.p_offset,
                 &phdr.p_vaddr,
                 &phdr.p_paddr,
                 &phdr.p_filesz,
                 &phdr.p_memsz,
                 &phdr.p_align,

                 &shdr.section_name,
                 &shdr.section_hdr.sh_name,
                 &shdr.section_hdr.sh_type,
                 &shdr.section_hdr.sh_flags,
                 &shdr.section_hdr.sh_addr,
                 &shdr.section_hdr.sh_offset,
                 &shdr.section_hdr.sh_size,
                 &shdr.section_hdr.sh_link,
                 &shdr.section_hdr.sh_info,
                 &shdr.section_hdr.sh_addralign,
                 &shdr.section_hdr.sh_entsize,

                 &sym.symbol_name,
                 &sym.file_name,
                 &sym.ref_name,
                 &sym.version,
                 &sym.symbol.st_name,
                 &sym.symbol.st_info,
                 &sym.symbol.st_other,
                 &sym.symbol.st_shndx,
                 &sym.symbol.st_value,
                 &sym.symbol.st_size,

                 &dependName);

    if (!tn) {
        goto out_tpl_map;
    }

    tpl_pack(tn, 0);

    // pack the program headers
    int i;
    for(i = 0; i < (int)elfdata->nr_phdrs; i++) {
        phdr = elfdata->program_headers[i];
        tpl_pack(tn, 1);
    }

    // pack the section headers
    for (iter = g_list_first(elfdata->section_headers); iter != NULL; iter = g_list_next(iter)) {
        shdr = *(elf_sct_hdr*)iter->data;
        tpl_pack(tn, 2); /* section name and attributes */
    }

    // loop to pack symbols
    for (iter = g_list_first(elfdata->symbols); iter != NULL; iter = g_list_next(iter)) {
        sym = *(elf_symbol*)iter->data;
        tpl_pack(tn, 3);  /* symbol name */
    }

    // loop to pack dependencies
    for (iter = g_list_first(elfdata->dependencies); iter != NULL; iter = g_list_next(iter)) {
        dependName = (char *) iter->data;
        tpl_pack(tn, 4);  /* dependencies */
    }

    tpl_dump(tn, TPL_MEM, &tplbuf, &tplsize);

    b64 = b64_encode(tplbuf, tplsize);
    if (!b64) {
        goto out_base64_error;
    }

    tpl_free(tn);
    free(tplbuf);

    *serial_data = b64;
    *serial_data_size = strlen(b64) + 1;

    return 0;

out_base64_error:
    b64_free(tplbuf);
    tpl_free(tn);
out_tpl_map:
err_no_filename:
    dlog(0, "Seriazation Error\n");
    *serial_data = NULL;
    *serial_data_size = 0;
    return -1;
}

static int elfheader_type_unserialize_data(char *sd, size_t sd_size, measurement_data **d)
{
    if(sd == NULL || d == NULL) {
        return -EINVAL;
    }

    int ret_val = 0;
    elfheader_meas_data *elfdata = NULL;
    tpl_node *tn;
    void *tplbuf;
    size_t tplsize;
    GList *iter;
    char *sectName = NULL;
    uint32_t sh_name, sh_type, sh_link, sh_info;
    uint64_t sh_flags, sh_addr, sh_offset;
    uint64_t sh_size, sh_addralign, sh_entsize;
    char *symbolName = NULL;
    char *fileName = NULL;
    char *refName = NULL;
    int version;
    uint64_t st_name, st_shndx, st_value, st_size;
    char st_info, st_other;
    char * dependName = NULL;

    GElf_Phdr phdr		= {0};
    GElf_Shdr *shdr		= NULL;
    elf_symbol * elfSym		= NULL;
    elf_sct_hdr *elfSectHdr	= NULL;

    tplbuf = b64_decode(sd, &tplsize);
    if(!tplbuf) {
        dlog(0, "Could Not Decode Data??? \n");
        goto error_base64_decode;
    }

    measurement_data *tempdata = alloc_measurement_data(&elfheader_measurement_type);
    if (tempdata == NULL) {
        dlog(0, "Could Not Allocate Libelf Measurement Data\n");
        goto error_alloc_elfdata;
    }
    elfdata = container_of(tempdata, elfheader_meas_data, d);

    tn = tpl_map("sc#vvuUUUuvvvvvv"  /* ELF header info */
                 "A(uuUUUUUU)"       /* Program headers */
                 "A(suuUUUUuuUU)"    /* Section headers */
                 "A(sssiUccUUU)"     /* Symbols */
                 "A(s)",             /* Dependencies */
                 &elfdata->filename,
                 elfdata->elf_header.e_ident, 16,
                 &elfdata->elf_header.e_type,
                 &elfdata->elf_header.e_machine,
                 &elfdata->elf_header.e_version,
                 &elfdata->elf_header.e_entry,
                 &elfdata->elf_header.e_phoff,
                 &elfdata->elf_header.e_shoff,
                 &elfdata->elf_header.e_flags,
                 &elfdata->elf_header.e_ehsize,
                 &elfdata->elf_header.e_phentsize,
                 &elfdata->elf_header.e_phnum,
                 &elfdata->elf_header.e_shentsize,
                 &elfdata->elf_header.e_shnum,
                 &elfdata->elf_header.e_shstrndx,
                 &phdr.p_type,
                 &phdr.p_flags,
                 &phdr.p_offset,
                 &phdr.p_vaddr,
                 &phdr.p_paddr,
                 &phdr.p_filesz,
                 &phdr.p_memsz,
                 &phdr.p_align,
                 &sectName,
                 &sh_name, &sh_type,
                 &sh_flags, &sh_addr, &sh_offset, &sh_size, &sh_link, &sh_info,
                 &sh_addralign, &sh_entsize,
                 &symbolName, &fileName, &refName,
                 &version, &st_name, &st_info, &st_other, &st_shndx, &st_value, &st_size,
                 &dependName);

    if(!tn) {
        goto error_tpl_map;
    }

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);
    if(tpl_unpack(tn, 0) < 0) { /* p_align */
        goto error_tpl_unpack_0;
    }

    int nr_phdrs = tpl_Alen(tn, 1);
    if(nr_phdrs < 0) {
        goto error_tpl_alen;
    }

    elfdata->nr_phdrs = (size_t)nr_phdrs;
    elfdata->program_headers = calloc(elfdata->nr_phdrs,
                                      sizeof(GElf_Phdr));
    if(elfdata->program_headers == NULL) {
        goto error_alloc_phdrs;
    }
    size_t i;
    for(i=0; i<elfdata->nr_phdrs; i++) {
        if(tpl_unpack(tn, 1) < 0) {
            goto error_unpack_phdr;
        }
        elfdata->program_headers[i] = phdr;
    }

    // Unpack Sections
    while (tpl_unpack(tn, 2) > 0) {
        // copy elements to header
        elfSectHdr = malloc(sizeof(elf_sct_hdr));
        if(elfSectHdr == NULL) {
            dlog(0, "Error allocating elf section header record\n");
            goto error_alloc_elfsecthdr;
        }

        dlog(5, "Unpack Section Name %s\n", sectName ? sectName : "(null)");
        elfSectHdr->section_hdr.sh_name		= sh_name;
        elfSectHdr->section_hdr.sh_type		= sh_type;
        elfSectHdr->section_hdr.sh_flags	= sh_flags;
        elfSectHdr->section_hdr.sh_offset	= sh_offset;
        elfSectHdr->section_hdr.sh_size		= sh_size;
        elfSectHdr->section_hdr.sh_link		= sh_link;
        elfSectHdr->section_hdr.sh_info		= sh_info;
        elfSectHdr->section_hdr.sh_addralign	= sh_addralign;
        elfSectHdr->section_hdr.sh_entsize	= sh_entsize;
        elfSectHdr->section_name		= sectName;
        sectName				= NULL;

        // append new section header to list of section headers
        elfdata->section_headers = g_list_append(elfdata->section_headers, elfSectHdr);
        continue;

error_alloc_elfsecthdr:
        free(sectName);
        goto error_section_processing;
    }


    // unpack symbols
    while (tpl_unpack(tn, 3) > 0) {
        elfSym = malloc(sizeof(elf_symbol));
        if(elfSym == NULL) {
            dlog(0, "Failed to allocate elf symbol entry\n");
            goto error_alloc_elfsym;
        }

        elfSym->version = version;
        elfSym->symbol.st_name	= st_name;
        elfSym->symbol.st_info	= st_info;
        elfSym->symbol.st_other = st_other;
        elfSym->symbol.st_shndx = st_shndx;
        elfSym->symbol.st_value = st_value;
        elfSym->symbol.st_size	= st_size;
        elfSym->symbol_name	= symbolName;
        elfSym->file_name	= fileName;
        elfSym->ref_name	= refName;
        symbolName		= NULL;
        fileName		= NULL;
        refName			= NULL;

        elfdata->symbols = g_list_append(elfdata->symbols, elfSym);

        continue;

error_alloc_elfsym:
        free(symbolName);
        free(fileName);
        free(refName);
        goto error_symbol_processing;
    }


    // unpack dependencies
    while (tpl_unpack( tn, 4) > 0) {
        elfdata->dependencies = g_list_append(elfdata->dependencies, dependName);
    }

    elfdata->d.type = &elfheader_measurement_type;

    tpl_free(tn);
    b64_free(tplbuf);
    *d = &elfdata->d;
    return ret_val;

error_symbol_processing:
error_section_processing:
error_unpack_phdr:
error_alloc_phdrs:
error_tpl_alen:
error_tpl_unpack_0:
    tpl_free(tn);
error_tpl_map:
    free_measurement_data(&elfdata->d);
error_alloc_elfdata:
    b64_free(tplbuf);
error_base64_decode:
    *d = NULL;
    return -1;
}

static int get_feature(measurement_data *d, char *feature, GList **out)
{
    if(d == NULL || feature == NULL || out == NULL) {
        return -EINVAL;
    }
    elfheader_meas_data *elfdata = (elfheader_meas_data *)d;
    GList *res = NULL;
    GList *iter;
    mode_t mode_filter;
    char * filename;

    if (strcmp(feature, "files") == 0) {
        mode_filter = 0;
    } else {
        return -ENOENT;
    }

    // Mode Filter 0 -> Return List of Files that original file depends on
    if (mode_filter == 0) {
        for (iter = g_list_first(elfdata->dependencies); iter != NULL; iter = g_list_next(iter)) {

            char * dependency = (char *) iter->data;

            filename = strdup(dependency);
            if (filename == NULL) {
                dlog(0, "Insuffiecent Memory to Allocate String\n");
                goto memerror;
            }
            res = g_list_append(res, filename);
        }
    }
    *out = res;
    return 0;

memerror:
    dlog(0, "Get Feature Error\n");
    g_list_free_full(res, free);
    *out = NULL;
    return -ENOMEM;
}

static const char *str_of_phdr_type(Elf64_Word p_type)
{
    switch(p_type) {
    case PT_NULL:
        return "PT_NULL";
    case PT_LOAD:
        return "PT_LOAD";
    case PT_DYNAMIC:
        return "PT_DYNAMIC";
    case PT_INTERP:
        return "PT_INTERP";
    case PT_NOTE:
        return "PT_NOTE";
    case PT_SHLIB:
        return "PT_SHLIB";
    case PT_PHDR:
        return "PT_PHDR";
    case PT_TLS:
        return "PT_TLS";
    case PT_NUM:
        return "PT_NUM";
    case PT_LOOS:
        return "PT_LOOS";
    case PT_GNU_EH_FRAME:
        return "PT_GNU_EH_FRAME";
    case PT_GNU_STACK:
        return "PT_GNU_STACK";
    case PT_GNU_RELRO:
        return "PT_GNU_RELRO";
//    case PT_LOSUNW: return "PT_LOSUNW";
    case PT_SUNWBSS:
        return "PT_SUNWBSS";
    case PT_SUNWSTACK:
        return "PT_SUNWSTACK";
//    case PT_HISUNW: return "PT_HISUNW";
    case PT_HIOS:
        return "PT_HIOS";
    case PT_LOPROC:
        return "PT_LOPROC";
    case PT_HIPROC:
        return "PT_HIPROC";
    }
    return "UNKNOWN";
}

static int human_readable(measurement_data *d, char **out, size_t *outsize)
{
    if(d == NULL || out == NULL || outsize == NULL) {
        return -EINVAL;
    }

    elfheader_meas_data *ed = container_of(d, elfheader_meas_data, d);
    char *buf = g_strdup_printf("file: %s\n", ed->filename);
    if(buf == NULL) {
        goto error;
    }
    size_t bufsz = strlen(buf)+1;

    int i = 0;
    for(i = 0; i < ed->nr_phdrs; i++) {
        GElf_Phdr *phdr = &ed->program_headers[i];
        char *pbuf = g_strdup_printf("phdr[%d]: {\n"
                                     "\ttype:   %s\n"
                                     "\tflags:  %c%c%c [%0"PRIx64"]\n"
                                     "\toffset: %016"PRIx64"\n"
                                     "\tvaddr:  %016"PRIx64"\n"
                                     "\tpaddr:  %016"PRIx64"\n"
                                     "\tfilesz: %016"PRIx64"\n"
                                     "\tmemsz:  %016"PRIx64"\n"
                                     "\talign:  %016"PRIx64"\n"
                                     "}\n",
                                     i,
                                     str_of_phdr_type(phdr->p_type),
                                     phdr->p_flags & PF_R ? 'R' : '-',
                                     phdr->p_flags & PF_W ? 'W' : '-',
                                     phdr->p_flags & PF_X ? 'X' : '-',
                                     (long unsigned)phdr->p_flags,
                                     phdr->p_offset,
                                     phdr->p_vaddr, phdr->p_paddr,
                                     phdr->p_filesz, phdr->p_memsz,
                                     phdr->p_align);
        if(pbuf == NULL) {
            goto error;
        }
        size_t len = strlen(pbuf);
        char *tmp = g_realloc(buf, bufsz + len);
        if(tmp == NULL) {
            g_free(pbuf);
            goto error;
        }
        buf = tmp;
        strcat(buf, pbuf);
        bufsz += len;
        g_free(pbuf);
    }

    int hnum = 0;
    GList *iter;
    for(iter = g_list_first(ed->section_headers); iter != NULL; iter = g_list_next(iter)) {
        struct elf_section_header *shdr = (struct elf_section_header *)iter->data;
        char *sbuf = g_strdup_printf("shdr[%d]: {\n"
                                     "\tname: %s\n"
                                     "\toffset: %0"PRIx64"\n"
                                     "\tsize:   %0"PRIx64"\n"
                                     "}\n",
                                     hnum++,
                                     shdr->section_name,
                                     shdr->section_hdr.sh_offset,
                                     shdr->section_hdr.sh_size);
        if(sbuf == NULL) {
            goto error;
        }

        size_t len = strlen(sbuf);
        char *tmp = g_realloc(buf, bufsz + len);
        if(tmp == NULL) {
            g_free(sbuf);
            goto error;
        }
        buf = tmp;
        strcat(buf, sbuf);
        bufsz += len;
        g_free(sbuf);
    }

    *out = buf;
    *outsize = bufsz;
    return 0;

error:
    g_free(buf);
    return -1;
}

struct measurement_type elfheader_measurement_type = {
    .magic     		= LIBELF_TYPE_MAGIC,
    .name	       	= LIBELF_TYPE_NAME,
    .alloc_data		= elfheader_type_alloc_data,
    .copy_data		= copy_elfheader_measurement_data,
    .free_data		= elfheader_type_free_data,
    .serialize_data	= elfheader_type_serialize_data,
    .unserialize_data	= elfheader_type_unserialize_data,
    .get_feature        = get_feature,
    .human_readable     = human_readable
};
