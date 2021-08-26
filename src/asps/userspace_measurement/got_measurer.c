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

// Goal: get all of the GOTs and detailed information on each entry and
// on what that entry points to.

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unistd.h>
#include <assert.h>

#include <elf.h>
#include <link.h>

#include <glib.h>
#include <gelf.h>
#include <libelf.h>

#include <util/util.h>

#include "memory.h"

/*********
 * Knobs *
 *********/
// Viewing the contents of /proc/<PID>/stat as an array of space
// separated entries, this is the one-up index of the startcode entry,
// which should hold the base load address of the executable's
// memory mapping. See `man 5 proc`
#define STAT_STARTCODE_INDEX 26

// Ignore GNU indirect functions that we can't verify because they
// don't have a corresponding R_X86_64_IRELATIVE relocations.
#define IGNORE_IFUNCS

//#define DEBUG_LINK_MAP_ORDER
//#define DEBUG_DEPENDENCIES
//#define DEBUG 0
//#define GOT_DEBUG
//#define DEBUG_SYMBOL_RESOLUTION
//#define DEBUG_ON_DISK_GOT
//#define SHOW_UNPARSED_DYNAMIC_ENTRIES

// Used to enable things that are probably highly platform dependent.
//#define EXPERIMENTAL

// GNU_HASH bloom filter
#define ELFCLASS_BITS 64
typedef uint64_t bloom_t;

/*********
 * Handy *
 *********/
// Get the number of bytes between two addresses
#define PTR_DIFF(p1, p2) ((void *) (p1) - (void *) (p2))

typedef struct {
    uint64_t *got;  // a copy of the GOT
    uint64_t vaddr; // virtual address corresponding to the first GOT entry
    size_t sz;      // the size of got in bytes
} got;

typedef struct {
    Elf *elfp;
    GElf_Ehdr ehdr;
    char *path;
    char *buf;
    uint64_t base_address;
    size_t sz;
    uint64_t dynamic_address;
    size_t dynamic_sz;
    GSList *neededs;
    uint64_t init;
    Elf_Data *symtab;
    int symbolic;
    int relro;
    char *strtab;
    size_t strtab_sz;
    size_t symtab_sz;
    size_t syment_sz;
    Elf_Data *rela;
    size_t rela_sz;
    Elf_Data *jmprel;
    size_t jmprel_sz;
    uint32_t *gnu_hash;
    uint64_t linkmap_address;
    char *soname;
    uint32_t *hash;
    size_t hash_sz;
    Elf64_Versym *versym;
    size_t versym_sz;
    Elf64_Verneed *verneed;
    Elf64_Verdef *verdef;
    got on_disk_got;
    uint64_t vaddr_adjustment;
} elf_context;

typedef struct {
    // Info from the ELF we're scanning
    uint64_t address;
    uint32_t relocation_type;
    unsigned char st_info;
    char *symbol_name;
    uint64_t contents;
    uint64_t *pointer_to_original_contents;
    // Symbol version info
    char *symbol_version;
    uint8_t hidden;
    char *expected_library;
    // Info from the address stored in the GOT
    char *matching_library;
    // The same address often maps to multiple symbols (e.g. putc,
    // _IO_putc, __GI__IO_putc in libc-2.17.so)
    GSList *matching_symbols;
} got_entry;

typedef struct {
    const char *symbol_name;
    uint64_t address;
    char *library;
    char *symbol_version;
    unsigned char st_info;
    unsigned char st_other;
    uint16_t st_shndx;
} symbol_resolution;

typedef struct {
    char *name;
    char *version;
    uint8_t hidden;
} got_symbol_match;

// Wrapper for a struct link_map read from another process to preserve
// its original address.
typedef struct {
    struct link_map link_map;
    uint64_t address;
} link_map_wrapper;


/***********
 * Globals *
 ***********/

// Globally unique symbol resolutions for symbols with STB_GNU_UNIQUE
// binding.
static GSList *unique_symbol_resolutions = NULL;

static int passed = TRUE;

//Represents the largest PID that can be had on the system.
//See get_pid_max_linux_64bit for details
uint32_t g_max_system_pid;

//Represents the number of digits that the largest PID can be represented in
uint32_t g_num_digits_pid;

/* *
 * On Linux 64 bit systems after kernel version 2.5, the highest PID
 * is read from the file "/proc/sys/kernel/pid_max" and can be as high
 * as 2^22. This returns the max PID, or zero if the file cannot be read.
 * Optionally, can provide argument to get back the number of digits
 * required to represent the value
 */
uint32_t get_pid_max_linux_64bit(uint32_t *num_digits)
{
    uint32_t pid_max;
    FILE *fp = fopen("/proc/sys/kernel/pid_max", "r");

    if (fp == NULL) {
        return 0;
    }

    if (fscanf(fp, "%" SCNu32 "", &pid_max) != 1) {
        pid_max = 0;
        goto close;
    }

    if(num_digits != NULL) {
        *num_digits = (uint32_t)floor(log10(pid_max)) + 1;
    }

    dlog(4, "The maximum PID on this system is %" PRIu32 "", pid_max);
    dlog(4, "The maximum size of a PID on this system is %" PRIu32 "\n", *num_digits);

close:
    fclose(fp);
    return pid_max;
}

static void report_anomaly(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    dlog(1, "Anomaly detected: ");
    vprintf(format, ap);
    printf("\n");
    va_end(ap);
    passed = FALSE;
}

static void report_anomaly_in_ctx(elf_context *ctx, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    dlog(1, "Anomaly detected in %s ELF object loaded at %#lx: \n",
         ctx->path, ctx->base_address);
    vprintf(format, ap);
    printf("\n");
    va_end(ap);
    passed = FALSE;
}

// Given an ELF header, zero out the section header table fields.
// This is necessary for using libelf to process the ELF object because
// it automatically tries to do section header table parsing.
static int zero_out_sht_fields(char *ehdr)
{
    if (ehdr[EI_CLASS] == ELFCLASS32) {
        Elf32_Ehdr *e = (Elf32_Ehdr *)ehdr;
        e->e_shoff = 0;
        e->e_shentsize = 0;
        e->e_shnum = 0;
        e->e_shstrndx = 0;
    } else if (ehdr[EI_CLASS] == ELFCLASS64) {
        Elf64_Ehdr *e = (Elf64_Ehdr *)ehdr;
        e->e_shoff = 0;
        e->e_shentsize = 0;
        e->e_shnum = 0;
        e->e_shstrndx = 0;
    } else {
        report_anomaly("Unknown ELF class: %hhd", ehdr[EI_CLASS]);
        return -1;
    }

    return 0;
}


static void free_elf_context(elf_context *ctx)
{
    if(!ctx) {
        return;
    }
    elf_end(ctx->elfp);
    g_slist_free(ctx->neededs);
    //Shallow copy of the file mapping buffer except for VDSO
    if(ctx->path && !strcmp(ctx->path, "[vdso]")) {
        free(ctx->buf);
    }
    //Data in elf (pointers into elf memory)
    //free(ctx->symtab->d_buf);
    //free(ctx->jmprel->d_buf);
    //free(ctx->rela->d_buf);
    //free(ctx->hash);
    //free(ctx->soname);
    //free(ctx->versym);
    free(ctx->on_disk_got.got);
    free(ctx);
}


static void read_verdef(
    elf_context *ctx,
    uint64_t verdef_addr,
    size_t verdef_num)
{
    // gelf_getverdef() doesn't really buy us anything because in
    // order to use that, we have to first figure out the size of the
    // section to get the Elf_Data*, but we don't know the size of
    // the section until we traverse the lists.

    // The Verdef structure is the same size for 32 and 64 bit
    char *p = ctx->buf + verdef_addr - ctx->base_address;
    size_t verdef_count = 0;
    uint32_t next_offset = 0;

    // TODO SECURITY WARNING: both this loop and the inner loop rely on the
    // data to determine when to stop iterating. We need to get the
    // bounds on VERDEF and use that as a guard.
    do {
        p += next_offset;
        Elf64_Verdef *verdef = (Elf64_Verdef *) p;
#ifdef DEBUG
        printf("Reading VERDEF %d\n", verdef->vd_ndx);
#endif
        int n_verdaux = 0;
        next_offset = verdef->vd_aux;
        // The Verdaux structure is the same size for 32 and 64 bit
        Elf64_Verdaux *verdaux = NULL;
        while (next_offset != 0) {
            p += next_offset;
            verdaux = (Elf64_Verdaux *) p;
            next_offset = verdaux->vda_next;
            ++n_verdaux;

#ifdef DEBUG
            printf("Read Verdaux %s\n", verdaux->vda_name + ctx->strtab);
#endif

        }

        if (n_verdaux != verdef->vd_cnt) {
            report_anomaly_in_ctx(ctx, "VERDEF entry %d had a different number "
                                  "of versions (Verdaux structures) than expected: expected "
                                  "%d, found %d", verdef->vd_ndx, verdef->vd_cnt, n_verdaux);
        }

        next_offset = verdef->vd_next;
        ++verdef_count;
        p = (char *) verdef;
    } while (next_offset);

    if (verdef_count != verdef_num) {
        report_anomaly_in_ctx(ctx, "VERDEF had a different number "
                              "of Verdef structures than expected: expected "
                              "%d, found %d", verdef_num, verdef_count);
    }

    ctx->verdef = (Elf64_Verdef *) (ctx->buf + verdef_addr - ctx->base_address);
}


static void read_verneed(
    elf_context *ctx,
    uint64_t verneed_addr,
    size_t verneed_num)
{
    // gelf_getverneed() doesn't really buy us anything because in
    // order to use that, we have to first figure out the size of the
    // section to get the Elf_Data*, but we don't know the size of
    // the section until we traverse the lists.

    // The Verneed structure is the same size for 32 and 64 bit
    char *p = ctx->buf + verneed_addr - ctx->base_address;
    size_t verneed_count = 0;
    uint32_t next_offset = 0;

    // TODO SECURITY WARNING: both this loop and the inner loop rely on the
    // data to determine when to stop iterating. We need to get the
    // bounds on VERNEED and use that as a guard.
    do {
        p += next_offset;
        Elf64_Verneed *verneed = (Elf64_Verneed *) p;
#ifdef DEBUG
        printf("Reading VERNEED for %s\n", verneed->vn_file + ctx->strtab);
#endif
        int n_vernaux = 0;
        next_offset = verneed->vn_aux;
        // The Vernaux structure is the same size for 32 and 64 bit
        Elf64_Vernaux *vernaux = NULL;
        while (next_offset != 0) {
            p += next_offset;
            vernaux = (Elf64_Vernaux *) p;
            next_offset = vernaux->vna_next;
            ++n_vernaux;

#ifdef DEBUG
            printf("Read Vernaux %s : %d\n", vernaux->vna_name + ctx->strtab, vernaux->vna_other);
#endif

        }

        if (n_vernaux != verneed->vn_cnt) {
            report_anomaly_in_ctx(ctx, "VERNEED entry %s had a different number "
                                  "of versions (Vernaux structures) than expected: expected "
                                  "%d, found %d", verneed->vn_file + ctx->strtab,
                                  verneed->vn_cnt, n_vernaux);
        }

        next_offset = verneed->vn_next;
        ++verneed_count;
        p = (char *) verneed;
    } while (next_offset);

    if (verneed_count != verneed_num) {
        report_anomaly_in_ctx(ctx, "VERNEED had a different number "
                              "of Verneed structures than expected: expected "
                              "%d, found %d", verneed_num, verneed_count);
    }

    ctx->verneed = (Elf64_Verneed *) (ctx->buf + verneed_addr - ctx->base_address);
}


static uint16_t lookup_versym_value(
    int sym_ndx,
    elf_context *ctx)
{
    if(sym_ndx < 0) {
        report_anomaly_in_ctx(ctx, "Failed to look up VERSYM entry: "
                              "symbol index %d out of bounds",
                              sym_ndx);
        return (uint16_t)(-1);
    }

    if ((unsigned int)sym_ndx * sizeof(ctx->versym[0]) > ctx->versym_sz) {
        GElf_Sym sym = {0};
        char *name = "(unknown)";
        if (gelf_getsym(ctx->symtab, sym_ndx, &sym) == &sym) {
            name = ctx->strtab + sym.st_name;
        }
        report_anomaly_in_ctx(ctx, "Failed to look up VERSYM entry "
                              "for %s: symbol index %d out of bounds",
                              name, sym_ndx);
        return (uint16_t)(-1);
    }
    return ctx->versym[sym_ndx];
}


static char *lookup_version_verdef(
    int versym_value,
    elf_context *ctx)
{
    unsigned char *p = (unsigned char *) ctx->verdef;
    unsigned int next_offset = 0;

    do {
        p += next_offset;
        Elf64_Verdef *verdef = (Elf64_Verdef *) p;
        if (verdef->vd_ndx == versym_value) {
            Elf64_Verdaux *verdaux = NULL;
            p += verdef->vd_aux;
            verdaux = (Elf64_Verdaux *) p;
            return verdaux->vda_name + ctx->strtab;

            // There could be additional lower versions, but we don't
            // care. If one ELF says it needs version 2.5 of a symbol
            // and we say it's linked to 2.6, it's fine.
        }

        next_offset = verdef->vd_next;
        p = (unsigned char *) verdef;
    } while (next_offset);

    report_anomaly_in_ctx(ctx,
                          "Failed to find version definition for VERSYM value %d in %s",
                          versym_value,
                          ctx->path);

    return NULL;
}


static int lookup_version_verneed(
    uint16_t versym_value,
    elf_context *ctx,
    char **library_name_out,
    char **version_name_out)
{
    char *p = (char *) ctx->verneed;
    uint32_t next_offset = 0;

    do {
        p += next_offset;
        Elf64_Verneed *verneed = (Elf64_Verneed *) p;
        int n_vernaux = 0;
        next_offset = verneed->vn_aux;
        Elf64_Vernaux *vernaux = NULL;
        while (next_offset != 0 &&
                n_vernaux < verneed->vn_cnt) {
            p += next_offset;
            vernaux = (Elf64_Vernaux *) p;
            next_offset = vernaux->vna_next;
            ++n_vernaux;

            if (vernaux->vna_other == versym_value) {
                *library_name_out = verneed->vn_file + ctx->strtab;
                *version_name_out = vernaux->vna_name + ctx->strtab;
                return 0;
            }
        }

        next_offset = verneed->vn_next;
        p = (char *) verneed;
    } while (next_offset);

    report_anomaly_in_ctx(ctx,
                          "Failed to find version needed for VERSYM value %d in %s",
                          versym_value,
                          ctx->path);

    return -1;
}

static int fill_in_symbol_version_info(
    int sym_ndx,
    int sym_st_shndx,
    elf_context *ctx,
    char **version_out,
    uint8_t *hidden_out,
    char **expected_library_out)
{
    char *ver = NULL;
    char *expected_library = NULL;
    if (ctx->versym != NULL) {
        uint16_t versym_value =
            lookup_versym_value(sym_ndx, ctx);
#define VERSYM_VALUE_MASK 0x7fff
#define VERSYM_HIDDEN_FLAG 0x8000
        uint16_t val = versym_value & VERSYM_VALUE_MASK;
        if (val > 1) {
            if (hidden_out != NULL) {
                *hidden_out =
                    (versym_value & VERSYM_HIDDEN_FLAG) != 0;
            }

            if (sym_st_shndx != SHN_UNDEF
                    && val != 1
                    && ctx->verdef != NULL) {
                ver = lookup_version_verdef(val, ctx);
                if (version_out != NULL) {
                    *version_out = ver;
                }
                if (expected_library_out != NULL) {
                    *expected_library_out = ctx->path;
                }
                return 0;
            }

            if (ver == NULL
                    && ctx->verneed != NULL) {
                if (lookup_version_verneed(val, ctx,
                                           &expected_library, &ver) == 0) {
                    if (version_out != NULL) {
                        *version_out = ver;
                    }
                    if (expected_library_out != NULL) {
                        *expected_library_out = expected_library;
                    }
                    return 0;
                }
            }
        }
    }

    return -1;
}

static link_map_wrapper *read_in_link_map_node(uint64_t addr)
{
    size_t read_sz = sizeof(struct link_map);
    link_map_wrapper *wrapper = malloc(sizeof(link_map_wrapper));
    if (wrapper == NULL) {
        goto error;
    }

    if (read_into(&(wrapper->link_map), addr, read_sz) < read_sz) {
        goto error;
    }

    // All of the pointers in the struct link_map are wrong now because
    // they're from the other address space. That's ok, except for
    // l_name. We need to pull the string in.
    // TODO: Buffer overflow concern?
    wrapper->link_map.l_name = read_string(
                                   (uint64_t) wrapper->link_map.l_name);
#ifdef DEBUG
    printf("Read link map entry %s at address %#lx\n",
           wrapper->link_map.l_name, addr);
#endif
    wrapper->address = addr;
    return wrapper;

error:
    if (wrapper) {
        free(wrapper);
    }

    return NULL;
}

static GSList *retrieve_link_map(uint64_t linkmap_addr)
{
    link_map_wrapper *wrap;
    GSList *list = g_slist_prepend(NULL,
                                   read_in_link_map_node(linkmap_addr));

    // Read succeeding nodes in
    link_map_wrapper *wrapper = list->data;
    while (wrapper->link_map.l_next != NULL) {
        wrap = read_in_link_map_node((uint64_t)wrapper->link_map.l_next);
        if (wrap == NULL) {
            goto error;
        }

        list = g_slist_prepend(list, wrap);
        wrapper = list->data;
    }
    list = g_slist_reverse(list);

    // Read in preceding nodes
    wrapper = list->data;
    while (wrapper->link_map.l_prev != NULL) {
        wrap = read_in_link_map_node((uint64_t)wrapper->link_map.l_prev);
        if (wrap == NULL) {
            goto error;
        }

        list = g_slist_prepend(list, wrap);
        wrapper = list->data;
    }

    goto end;

error:
    if (list) {
        g_slist_free(list);
        list = NULL;
    }

end:
    return list;
}


static int parse_vdso_dynamic(
    Elf *elfp,
    elf_context *ctx,
    GElf_Phdr *phdr)
{
    off_t offset = (off_t)(ctx->dynamic_address - ctx->base_address);
    Elf_Data *data = elf_getdata_rawchunk(elfp, offset, phdr->p_memsz,
                                          ELF_T_DYN);
    if (data == NULL) {
        dlog(4,"Error getting DYNAMIC data for %s from offset %ld: %s",
             ctx->path, offset, elf_errmsg(elf_errno()));
        return -1;
    }

    uint64_t strtab_addr = 0;
    size_t strtab_sz = 0;
    uint64_t symtab_addr = 0;
    size_t syment_sz = 0;
    uint64_t soname_strtab_offset = 0;
    uint64_t verneed_addr = 0;
    size_t verneed_num = 0;
    uint64_t versym_addr = 0;
    uint64_t verdef_addr = 0;
    size_t verdef_num = 0;

    /* This assignment is for the case there are no entries
     * (the likelihood of is basically 0, but it makes the
     * static analyzer happy */
    GElf_Dyn dyn;
    dyn.d_tag = DT_NULL;

    unsigned int i;
    unsigned int n_dyn = phdr->p_memsz / sizeof(ElfW(Dyn));
    for (i = 0; i < n_dyn; ++i) {
        /* i is converted to an unsigned value in the library code,
         * so this conversion is okay  */
        if (gelf_getdyn(data, (int)i, &dyn) != &dyn) {
            dlog(4,"Error getting DYNAMIC entry %d for %s: %s",
                 i, ctx->path, elf_errmsg(elf_errno()));
            return -1;
        }

        if (dyn.d_tag == DT_NULL) {
            break;
        }

        switch (dyn.d_tag) {
        case DT_NEEDED:
            ctx->neededs = g_slist_prepend(ctx->neededs,
                                           GINT_TO_POINTER(dyn.d_un.d_val));
            break;
        case DT_INIT:
            ctx->init = dyn.d_un.d_val;
            if (ctx->ehdr.e_type != ET_EXEC) {
                ctx->init += ctx->base_address;
            }
            break;
        case DT_STRTAB:
            strtab_addr = dyn.d_un.d_val - ctx->vaddr_adjustment;
            break;
        case DT_STRSZ:
            strtab_sz = dyn.d_un.d_val;
            break;
        case DT_SYMTAB:
            symtab_addr = dyn.d_un.d_val - ctx->vaddr_adjustment;
            break;
        case DT_SYMENT:
            syment_sz = dyn.d_un.d_val;
            break;
        case DT_SYMBOLIC:
            ctx->symbolic = TRUE;
            break;
        case DT_SONAME:
            soname_strtab_offset = dyn.d_un.d_val;
            break;
        case DT_VERNEED:
            verneed_addr = dyn.d_un.d_val - ctx->vaddr_adjustment;
            break;
        case DT_VERNEEDNUM:
            verneed_num = dyn.d_un.d_val;
            break;
        case DT_VERSYM:
            versym_addr = dyn.d_un.d_val - ctx->vaddr_adjustment;
            break;
        case DT_VERDEF:
            verdef_addr = dyn.d_un.d_val - ctx->vaddr_adjustment;
            break;
        case DT_VERDEFNUM:
            verdef_num = dyn.d_un.d_val;
            break;
        case DT_BIND_NOW:
            ctx->relro = TRUE;
            break;
        case DT_FLAGS:
            if (dyn.d_un.d_val & DF_SYMBOLIC) {
                ctx->symbolic = TRUE;
            }
            if (dyn.d_un.d_val & DF_BIND_NOW) {
                ctx->relro = TRUE;
            }
            break;
        case DT_FLAGS_1:
            if (dyn.d_un.d_val & DF_1_NOW) {
                ctx->relro = TRUE;
            }
            break;
        default:
#ifdef SHOW_UNPARSED_DYNAMIC_ENTRIES
            printf("Unparsed dynamic entry: d_tag: %#lx, d_val:%ld\n",
                   dyn.d_tag, dyn.d_un.d_val);
#endif
            break;
        }
    }
    if (dyn.d_tag != DT_NULL) {
        report_anomaly_in_ctx(ctx,
                              "Dynamic section did not contain DT_NULL");
    }

#define ASSERT_DYN_ENTRY_PRESENT(x, msg) if (!x) {\
        dlog(4,"Missing %s from dynamic section", msg);\
        return -1;\
    }
    ASSERT_DYN_ENTRY_PRESENT(strtab_addr, "DT_STRTAB");
    ASSERT_DYN_ENTRY_PRESENT(strtab_sz, "DT_STRSZ");
    ctx->strtab = ctx->buf + strtab_addr;
    ctx->strtab_sz = strtab_sz;

    ASSERT_DYN_ENTRY_PRESENT(symtab_addr, "DT_SYMTAB");
    // TODO is there a better way to get the size of the symbol table?
    // Supposedly you can get it from the hash table because they
    // cover the same number of symbols, but what if you don't have a
    // hash table (not GNU_HASH - does that have it)?
    size_t symtab_sz = (size_t)(strtab_addr - symtab_addr);
    if (strtab_addr < symtab_addr) {
        dlog(4,"STRTAB address (%#lx) was less than SYMTAB address (%#lx) "
             "- cannot estimate SYMTAB size", strtab_addr, symtab_addr);
        return -1;
    }
    /* The second argument for this function is a signed type, but we
     * are looking for the data at an unsigned address, hence the conversion */
    ctx->symtab = elf_getdata_rawchunk(elfp, (off_t)symtab_addr,
                                       symtab_sz, ELF_T_SYM);
    if (ctx->symtab == NULL) {
        dlog(4,"Error getting SYMTAB data for %s from address %#lx, offset "
             "from header %#lx", ctx->path, symtab_addr + ctx->base_address,
             symtab_addr);
        return -1;
    }
    ctx->symtab_sz = symtab_sz;

    if (ctx->ehdr.e_ident[EI_CLASS] == ELFCLASS32) {
        if (syment_sz != sizeof(Elf32_Sym)) {
            report_anomaly_in_ctx(ctx, "Unusual DT_SYMENT value: %ld "
                                  "instead of the expected %ld",
                                  syment_sz, sizeof(Elf32_Sym));
        }
    } else if (ctx->ehdr.e_ident[EI_CLASS] == ELFCLASS64) {
        if (syment_sz != sizeof(Elf64_Sym)) {
            report_anomaly_in_ctx(ctx, "Unusual DT_SYMENT value: %ld "
                                  "instead of the expected %ld",
                                  syment_sz, sizeof(Elf64_Sym));
        }
    } else {
        dlog(4,"Unrecognized ELF class: %d",
             ctx->ehdr.e_ident[EI_CLASS]);
        return -1;
    }
    ctx->syment_sz = syment_sz;

    if (ctx->neededs) {
#ifdef DEBUG
        fputs("NEEDEDs:", stdout);
#endif
        ctx->neededs = g_slist_reverse(ctx->neededs);
        GSList *p = ctx->neededs;
        for (; p != NULL; p = p->next) {
            p->data = ctx->strtab + GPOINTER_TO_INT(p->data);
#ifdef DEBUG
            if (p != ctx->neededs) {
                putchar(',');
            }
            printf(" %s", (char *) p->data);
#endif
        }
#ifdef DEBUG
        putchar('\n');
#endif
    }

#ifdef DEBUG
    printf("STRTAB at %#lx\n", strtab_addr);
    printf("STRTAB size: %ld\n", strtab_sz);
    printf("SYMTAB at %#lx\n", symtab_addr);
    printf("SYMTAB entry size: %ld\n", syment_sz);
    printf("SONAME STRTAB offset: %ld\n", soname_strtab_offset);
    printf("VERNEED at %#lx\n", verneed_addr);
    printf("VERNEEDNUM: %ld\n", verneed_num);
    printf("VERSYM at %#lx\n", versym_addr);
    if (verdef_addr != 0) {
        printf("VERDEF at %#lx\n", verdef_addr);
    }
#endif

    if (soname_strtab_offset > 0) {
        if (soname_strtab_offset <  ctx->strtab_sz) {
            ctx->soname = ctx->strtab + soname_strtab_offset;
#ifdef DEBUG
            printf("SONAME: %s\n", ctx->soname);
#endif
        } else {
#ifdef DEBUG
            printf("SONAME offset %ld exceeded STRTAB, size %zd\n",
                   soname_strtab_offset, ctx->strtab_sz);
#endif
            report_anomaly_in_ctx(ctx, "The DT_SONAME string table "
                                  "offset (%#lx) exceeded the string table size (%#zx)",
                                  soname_strtab_offset, ctx->strtab_sz);
        }
    }

    if (verneed_addr && verneed_num) {
        read_verneed(ctx, verneed_addr + ctx->base_address, verneed_num);
    }
    if (verdef_addr && verdef_num) {
        read_verdef(ctx, verdef_addr + ctx->base_address, verdef_num);
    }
    if (versym_addr && symtab_sz && syment_sz) {
        unsigned long num_symbols = (unsigned long)(symtab_sz / syment_sz);
        // VERSYM entries are the same size for 32 and 64 bit
        ctx->versym_sz = (size_t)(num_symbols * sizeof(Elf64_Versym));
        ctx->versym = (Elf64_Versym *) (ctx->buf + versym_addr);
#if DEBUG >= 2
        unsigned int i = 0;
        printf("VERSYM Table");
        for (i = 0; i < num_symbols; ++i) {
            if ((i & 3) == 0) {
                printf("\n %03x:", i);
            }
            printf(" %x", ctx->versym[i]);
        }
        putchar('\n');
#endif
    }

    return 0;
}

static int parse_dynamic(
    Elf *elfp,
    elf_context *ctx,
    GElf_Phdr *phdr)
{
    uint64_t offset = 0;
    if (ctx->ehdr.e_type != ET_EXEC) {
        offset += ctx->base_address;
    }
    // From the loaded memory image, the offset is p_vaddr
    offset += phdr->p_vaddr;
    ctx->dynamic_address = offset;

    // Adjust offset so it's an offset from the ELF header.
    // Above we computed the absolute address of the dynamic section in
    // the other process's image. Now we have to turn that into an
    // offset from the start of the ELF header.
    offset -= ctx->base_address;
    Elf_Data *data = elf_getdata_rawchunk(elfp, (off_t)offset, phdr->p_memsz,
                                          ELF_T_DYN);
    if (data == NULL) {
        dlog(4,"Error getting DYNAMIC data for %s from offset %#lx: %s",
             ctx->path, offset, elf_errmsg(elf_errno()));
        return -1;
    }

    uint64_t strtab_addr = 0;
    size_t strtab_sz = 0;
    uint64_t symtab_addr = 0;
    size_t syment_sz = 0;
    uint64_t rela_addr = 0;
    size_t rela_sz = 0;
    uint64_t jmprel_addr = 0;
    size_t jmprel_sz = 0;
    uint64_t got_addr = 0;
    uint64_t soname_strtab_offset = 0;
    uint64_t hash_addr = 0;
    uint64_t gnu_hash_addr = 0;
    uint64_t debug_addr = 0;
    uint64_t verneed_addr = 0;
    size_t verneed_num = 0;
    uint64_t versym_addr = 0;
    uint64_t verdef_addr = 0;
    size_t verdef_num = 0;
    unsigned int pltrel = 0;

    GElf_Dyn dyn = {0};
    unsigned int i;
    unsigned int n_dyn = phdr->p_memsz / sizeof(ElfW(Dyn));
    for (i = 0; i < n_dyn; ++i) {
        //The index is just converted to an unsigned int anyways in that function
        if (gelf_getdyn(data, (int)i, &dyn) != &dyn) {
            dlog(4,"Error getting DYNAMIC entry %d for %s: %s",
                 i, ctx->path, elf_errmsg(elf_errno()));
            return -1;
        }

        if (dyn.d_tag == DT_NULL) {
            break;
        }

        switch (dyn.d_tag) {
        case DT_NEEDED:
            ctx->neededs = g_slist_prepend(ctx->neededs,
                                           GINT_TO_POINTER(dyn.d_un.d_val));
            break;
        case DT_INIT:
            ctx->init = dyn.d_un.d_val;
            if (ctx->ehdr.e_type != ET_EXEC) {
                ctx->init += ctx->base_address;
            }
            break;
        case DT_STRTAB:
            strtab_addr = dyn.d_un.d_val;
            break;
        case DT_STRSZ:
            strtab_sz = dyn.d_un.d_val;
            break;
        case DT_SYMTAB:
            symtab_addr = dyn.d_un.d_val;
            break;
        case DT_SYMENT:
            syment_sz = dyn.d_un.d_val;
            break;
        case DT_RELA:
            rela_addr = dyn.d_un.d_val;
            break;
        case DT_RELASZ:
            rela_sz = dyn.d_un.d_val;
            break;
        case DT_JMPREL:
            jmprel_addr = dyn.d_un.d_val;
            break;
        case DT_PLTRELSZ:
            jmprel_sz = dyn.d_un.d_val;
            break;
        case DT_PLTREL:
            pltrel = dyn.d_un.d_val;
            if (pltrel != DT_RELA) {
                dlog(4,"Unrecognized PLTREL relocation type: %d",
                     pltrel);
                return -1;
            }
            break;
        case DT_PLTGOT:
            got_addr = dyn.d_un.d_val;
            break;
        case DT_SYMBOLIC:
            ctx->symbolic = TRUE;
            break;
        case DT_SONAME:
            soname_strtab_offset = dyn.d_un.d_val;
            break;
        case DT_HASH:
            hash_addr = dyn.d_un.d_val;
            break;
        case DT_GNU_HASH:
            gnu_hash_addr = dyn.d_un.d_val;
            break;
        case DT_DEBUG:
            debug_addr = dyn.d_un.d_val;
            break;
        case DT_VERNEED:
            verneed_addr = dyn.d_un.d_val;
            if (ctx->ehdr.e_type != ET_EXEC) {
                verneed_addr += ctx->base_address;
            }
            break;
        case DT_VERNEEDNUM:
            verneed_num = dyn.d_un.d_val;
            break;
        case DT_VERSYM:
            versym_addr = dyn.d_un.d_val;
            break;
        case DT_VERDEF:
            verdef_addr = dyn.d_un.d_val;
            if (ctx->ehdr.e_type != ET_EXEC) {
                verdef_addr += ctx->base_address;
            }
            break;
        case DT_VERDEFNUM:
            verdef_num = dyn.d_un.d_val;
            break;
        case DT_BIND_NOW:
            ctx->relro = TRUE;
            break;
        case DT_FLAGS:
            if (dyn.d_un.d_val & DF_SYMBOLIC) {
                ctx->symbolic = TRUE;
            }
            if (dyn.d_un.d_val & DF_BIND_NOW) {
                ctx->relro = TRUE;
            }
            break;
        case DT_FLAGS_1:
            if (dyn.d_un.d_val & DF_1_NOW) {
                ctx->relro = TRUE;
            }
            break;
        default:
#ifdef DEBUG
            printf("Unparsed dynamic entry: d_tag: %ld, d_val:%#lx\n",
                   dyn.d_tag, dyn.d_un.d_val);
#endif
            break;
        }
    }
    if (!n_dyn || dyn.d_tag != DT_NULL) {
        report_anomaly_in_ctx(ctx,
                              "Dynamic section did not contain DT_NULL");
    }

    ASSERT_DYN_ENTRY_PRESENT(strtab_addr, "DT_STRTAB");
    ASSERT_DYN_ENTRY_PRESENT(strtab_sz, "DT_STRSZ");
    ctx->strtab = ctx->buf + (strtab_addr - ctx->base_address);
    ctx->strtab_sz = strtab_sz;

    ASSERT_DYN_ENTRY_PRESENT(symtab_addr, "DT_SYMTAB");
    // TODO is there a better way to get the size of the symbol table?
    // Supposedly you can get it from the hash table because they
    // cover the same number of symbols, but what if you don't have a
    // hash table (not GNU_HASH - does that have it?)?
    size_t symtab_sz = strtab_addr - symtab_addr;
    if (strtab_addr < symtab_addr) {
        dlog(4,"STRTAB address (%#lx) was less than SYMTAB address (%#lx) "
             "- cannot estimate SYMTAB size", strtab_addr, symtab_addr);
        return -1;
    }

    /* Unlikely that this conversion would overflow a signed type, but that's the type
       that the function takes */
    ctx->symtab = elf_getdata_rawchunk(elfp, (off_t)(symtab_addr - ctx->base_address),
                                       symtab_sz, ELF_T_SYM);
    if (ctx->symtab == NULL) {
        dlog(4,"Error getting SYMTAB data for %s from address %#lx, offset "
             "from header %#lx", ctx->path, symtab_addr,
             (uint64_t)symtab_addr - ctx->base_address);
        return -1;
    }
    ctx->symtab_sz = symtab_sz;

    if (ctx->ehdr.e_ident[EI_CLASS] == ELFCLASS32) {
        if (syment_sz != sizeof(Elf32_Sym)) {
            report_anomaly_in_ctx(ctx, "Unusual DT_SYMENT value: %ld "
                                  "instead of the expected %ld",
                                  syment_sz, sizeof(Elf32_Sym));
        }
    } else if (ctx->ehdr.e_ident[EI_CLASS] == ELFCLASS64) {
        if (syment_sz != sizeof(Elf64_Sym)) {
            report_anomaly_in_ctx(ctx, "Unusual DT_SYMENT value: %ld "
                                  "instead of the expected %ld",
                                  syment_sz, sizeof(Elf64_Sym));
        }
    } else {
        dlog(4,"Unrecognized ELF class: %d",
             ctx->ehdr.e_ident[EI_CLASS]);
        return -1;
    }
    ctx->syment_sz = syment_sz;

    if (ctx->neededs) {
#ifdef DEBUG
        fputs("NEEDEDs:", stdout);
#endif
        ctx->neededs = g_slist_reverse(ctx->neededs);

        // Convert NEEDEDs from STRTAB offsets to actual STRTAB pointers
        GSList *p = ctx->neededs;
        for (; p != NULL; p = p->next) {
            p->data = ctx->strtab + GPOINTER_TO_INT(p->data);
#ifdef DEBUG_DEPENDENCIES
            printf("%s depends on %s\n", ctx->path, (char *) p->data);
#endif
#ifdef DEBUG
            if (p != ctx->neededs) {
                putchar(',');
            }
            printf(" %s", (char *) p->data);
#endif
        }
#ifdef DEBUG
        putchar('\n');
#endif
    }

#ifdef DEBUG
    printf("STRTAB at %#lx\n", strtab_addr);
    printf("STRTAB size: %ld\n", strtab_sz);
    printf("SYMTAB at %#lx\n", symtab_addr);
    printf("SYMTAB entry size: %ld\n", syment_sz);
    printf("RELA at %#lx\n", rela_addr);
    printf("RELA size: %ld\n", rela_sz);
    printf("RELA at %#lx\n", rela_addr);
    printf("JMPREL at %#lx\n", jmprel_addr);
    printf("GOT at %#lx\n", got_addr);
    printf("SONAME STRTAB offset: %ld\n", soname_strtab_offset);
    printf("HASH at %#lx\n", hash_addr);
    printf("GNU_HASH at %#lx\n", gnu_hash_addr);
    printf("DEBUG at %#lx\n", debug_addr);
    printf("VERNEED at %#lx\n", verneed_addr);
    printf("VERNEEDNUM: %ld\n", verneed_num);
    printf("VERSYM at %#lx\n", versym_addr);
    if (verdef_addr != 0) {
        printf("VERDEF at %#lx\n", verdef_addr);
    }
#endif

    if (rela_addr != 0 && rela_sz != 0) {
        // TODO support DT_REL (needed for 32 bit)
        ASSERT_DYN_ENTRY_PRESENT(rela_addr, "DT_RELA");
        ASSERT_DYN_ENTRY_PRESENT(rela_sz, "DT_RELASZ");
        /* Unlikely that this conversion would overflow a signed type, but that's the type
           that the function takes */
        ctx->rela = elf_getdata_rawchunk(elfp, (off_t)(rela_addr - ctx->base_address),
                                         rela_sz, ELF_T_RELA);
        if (ctx->rela == NULL) {
            dlog(4,"Error getting RELA data for %s from address %#lx, offset "
                 "from header %#lx", ctx->path, rela_addr,
                 rela_addr - ctx->base_address);
            return -1;
        }
        ctx->rela_sz = rela_sz;
    }

    if (jmprel_addr != 0 && jmprel_sz > 0) {
        // TODO use pltrel to support REL and RELA so we can handle 32 bit
        ctx->jmprel = elf_getdata_rawchunk(elfp, (off_t)(jmprel_addr - ctx->base_address),
                                           jmprel_sz, ELF_T_RELA);
        if (ctx->jmprel == NULL) {
            dlog(4,"Error getting JMPREL data for %s from address %#lx, offset "
                 "from header %#lx", ctx->path, jmprel_addr,
                 jmprel_addr - ctx->base_address);
            return -1;
        }
        ctx->jmprel_sz = jmprel_sz;
    }

    // DT_PLTGOT may be absent, e.g. if DF_BIND_NOW is present.
    uint64_t linkmap_addr = 0;
    if (got_addr) {
        // GOT[0] = address of .dynamic section (which we are parsing)
        // GOT[1] = address of struct link_map entry for this object
        // GOT[2] = address of symbol resolution function (e.g. dl_fixup)
        unsigned int got_entry_sz = 4;
        if (ctx->ehdr.e_ident[EI_CLASS] == ELFCLASS64) {
            got_entry_sz = 8;
        }
        uint64_t dynamic_addr = *(uint64_t *)(ctx->buf +
                                              (got_addr - ctx->base_address));

        if (ctx->ehdr.e_type != ET_EXEC) {
            // For shared objects, GOT[0] is an offset
            dynamic_addr += ctx->base_address;
        }
        if (dynamic_addr != ctx->dynamic_address) {
            report_anomaly_in_ctx(ctx, "The address of the .dynamic section "
                                  "recorded in GOT[0] (%#lx) did not match the address "
                                  "computed from the ELF header (%#lx)", dynamic_addr,
                                  ctx->dynamic_address);
        }
        linkmap_addr = *(uint64_t *)(ctx->buf +
                                     (got_addr + got_entry_sz - ctx->base_address));
#ifdef DEBUG
        printf("GOT[0] .dynamic address: %#lx\n", dynamic_addr);
#endif
    }
    if (soname_strtab_offset > 0) {
        if (soname_strtab_offset < ctx->strtab_sz) {
            ctx->soname = ctx->strtab + soname_strtab_offset;
#ifdef DEBUG
            printf("SONAME: %s\n", ctx->soname);
#endif
        } else {
#ifdef DEBUG
            printf("SONAME offset %ld exceeded STRTAB, size %zd\n",
                   soname_strtab_offset, ctx->strtab_sz);
#endif
            report_anomaly_in_ctx(ctx, "The DT_SONAME string table "
                                  "offset (%#lx) exceeded the string table size (%#zx)",
                                  soname_strtab_offset, ctx->strtab_sz);
        }
    }

    if (hash_addr != 0) {
        // Elf64_Word and Elf32_Word are both uint32_t
        uint32_t *p_hash = (uint32_t *)(ctx->buf +
                                        (hash_addr - ctx->base_address));
        uint32_t nbucket = p_hash[0];
        uint32_t nchain = p_hash[1];
        ctx->hash = p_hash;
        ctx->hash_sz = (2 + nbucket + nchain) * sizeof(uint32_t);
#ifdef DEBUG
        printf("Hash table: %d buckets, %d chains\n", nbucket, nchain);
#endif
    }

    if (gnu_hash_addr != 0) {
        ctx->gnu_hash = (uint32_t *)(ctx->buf +
                                     (gnu_hash_addr - ctx->base_address));
    }

    if (debug_addr) {
        struct r_debug rdbg = {0};
        read_into(&rdbg, debug_addr, sizeof(rdbg));
        if (linkmap_addr) {
            // Already got the link_map from GOT[1], verify
            if ((uint64_t) rdbg.r_map != linkmap_addr) {
                report_anomaly_in_ctx(ctx, "The address of the link_map "
                                      "recorded in GOT[1] (%#lx) did not match the address "
                                      "in r_debug.r_map (%#lx)", linkmap_addr,
                                      rdbg.r_map);
            }
        } else {
            linkmap_addr = (uint64_t) rdbg.r_map;
        }
    }

    if (linkmap_addr) {
#ifdef DEBUG
        printf("link_map address: %#lx\n", linkmap_addr);
#endif
        ctx->linkmap_address = linkmap_addr;
    }
    if (verneed_addr && verneed_num) {
        read_verneed(ctx, verneed_addr, verneed_num);
    }
    if (verdef_addr && verdef_num) {
        read_verdef(ctx, verdef_addr, verdef_num);
    }
    if (versym_addr && symtab_sz && syment_sz) {
        unsigned int num_symbols = symtab_sz / syment_sz;
        // VERSYM entries are the same size for 32 and 64 bit
        ctx->versym_sz = num_symbols * sizeof(Elf64_Versym);
        ctx->versym = (Elf64_Versym *) (ctx->buf + versym_addr -
                                        ctx->base_address);
#if DEBUG >= 2
        unsigned int i = 0;
        printf("VERSYM Table");
        for (i = 0; i < num_symbols; ++i) {
            if ((i & 3) == 0) {
                printf("\n %03x:", i);
            }
            printf(" %x", ctx->versym[i]);
        }
        putchar('\n');
#endif
    }

    return 0;
}

static void free_file_mapping(gpointer data, gpointer path)
{
    if(!data) {
        return;
    }
    memory_mapping *mapping = data;
    if (mapping->path != path) {
        free(mapping->path);
    }
    mapping->path = NULL;
    free(mapping->perms);
    mapping->perms = NULL;
    free(mapping);
}

static void free_mapping_group(mapping_group *grp)
{
    if (!grp) {
        return;
    }

    GSList *p;
    if (grp->mappings) {
        for (p = grp->mappings; p != NULL; p = p->next) {
            free_file_mapping(p->data, grp->path);
            p->data = NULL;
        }
        g_slist_free(grp->mappings);
        grp->mappings = NULL;
    }

    //have to be careful about clearing out shallow copies
    if (grp->path) {
        free(grp->path);
        grp->path = NULL;
    }

    free(grp);
}


static void free_file_mapping_buffer(gpointer data, gpointer free_buffer)
{
    file_mapping_buffer *mb = data;
    // Assume the path belongs to the mapping group and will be freed
    // there.
    mb->path = NULL;
    if (GPOINTER_TO_INT(free_buffer)) {
        free(mb->buf);
    }
    mb->buf = NULL;
    free(mb);
}


static int on_disk_elf_matches_ctx(
    GElf_Ehdr *ehdr,
    Elf *elfp,
    int fd,
    elf_context *ctx)
{
    size_t n_phdr = 0;
    if (elf_getphdrnum(elfp, &n_phdr) != 0) {
        report_anomaly_in_ctx(ctx, "failed to get program header count "
                              "from on-disk ELF file: %s - %s",
                              ctx->path, elf_errmsg(elf_errno()));
        return FALSE;
    }

    size_t i;
    GElf_Phdr phdr;
    for (i = 0; i < n_phdr; ++i) {
        if (gelf_getphdr(elfp, (int)i, &phdr) != &phdr) {
            dlog(4,"elf_getphdr() failed: %s", elf_errmsg(elf_errno()));
            return FALSE;
        }
        if (phdr.p_type == PT_LOAD
                && (phdr.p_flags & PF_R)
                && !(phdr.p_flags & PF_W)) {
#ifdef DEBUG
            printf("Verifying PT_LOAD segment: offset: %#lx, filesz: "
                   "%#lx, vaddr: %#lx, paddr: %#lx, memsz: %#lx\n",
                   phdr.p_offset, phdr.p_filesz, phdr.p_vaddr,
                   phdr.p_paddr, phdr.p_memsz);
#endif
            size_t sz = phdr.p_filesz;
            char *buf = calloc(1, sz);

            if (!buf) {
                dlog(4, "Unable to allocate memory for process ELF object buffer");
                return FALSE;
            }

            ssize_t bytes_read = pread(fd, buf, sz, (off_t)phdr.p_offset);
            if (bytes_read != (ssize_t) sz) {
                warn("Failed to read PT_LOAD segment from disk, %zd "
                     "bytes beginning at offset %#lx, read %zd bytes",
                     sz, phdr.p_offset, bytes_read);
                free(buf);
                return FALSE;
            }

            uint64_t mem_offset = phdr.p_vaddr;
            if (ehdr->e_type == ET_EXEC) {
                if (mem_offset < ctx->base_address) {
                    warn("PHDR virtual address %#lx is before the base address %#lx of ELF",
                         mem_offset, ctx->base_address);
                    free(buf);
                    return FALSE;
                }

                mem_offset -= ctx->base_address;
            }

            if (ctx->sz < sz) {
                dlog(4,"On-disk ELF contained larger PT_LOAD segment "
                     "than in-memory process");
                free(buf);
                return FALSE;
            }

            if (memcmp(buf, ctx->buf + mem_offset, sz) != 0) {
                report_anomaly_in_ctx(ctx, "PT_LOAD segment on disk "
                                      "didn't match process memory: file offset: %#lx "
                                      "filesz: %#lx, vaddr: %#lx, memsz: %#lx",
                                      phdr.p_offset, phdr.p_filesz, phdr.p_vaddr,
                                      phdr.p_memsz);
                free(buf);
                return FALSE;
            }
            free(buf);
        }
    }
    // TODO
    //  - Dynamic segment
    //      - exclude run-time entries
    //          - DT_DEBUG
    //  - .dynsym?
    //  - RELA tables?
    //  - VERSYM, VERDEF, VERNEED?
    return TRUE;
}


static void get_rela_min_max_got_offsets(
    Elf_Data *rela_data,
    int rela_limit,
    uint64_t *minimum_got_virtual_offset_out,
    uint64_t *maximum_got_virtual_offset_out)
{
    int i = 0;
    GElf_Rela rela;
    for (i = 0; i < rela_limit; ++i) {
        if (gelf_getrela(rela_data, i, &rela) != &rela) {
            break;
        }
        int r_type = ELF64_R_TYPE(rela.r_info);

        uint64_t addr = rela.r_offset;

        switch (r_type) {
        case R_X86_64_GLOB_DAT:
        // Fall-through
        case R_X86_64_JUMP_SLOT:
            if (addr < *minimum_got_virtual_offset_out
                    || *minimum_got_virtual_offset_out == 0) {
                *minimum_got_virtual_offset_out = addr;
            }
            if (addr > *maximum_got_virtual_offset_out) {
                *maximum_got_virtual_offset_out = addr;
            }
            break;
        default:
            // TODO other GOT relocations
            break;
        }
    }
}

// Walk the RELA tables and determine the bounds of the GOT
static int get_got_virtual_offset_bounds(
    elf_context *ctx,
    Elf *elfp,
    GElf_Ehdr *ehdr,
    size_t n_phdr,
    uint64_t *minimum_got_virtual_offset,
    uint64_t *maximum_got_virtual_offset)
{
    size_t phdr_ndx;
    GElf_Phdr phdr;
    uint64_t rela_addr = 0;
    size_t rela_sz = 0;
    uint64_t jmprel_addr = 0;
    size_t jmprel_sz = 0;
    for (phdr_ndx = 0; phdr_ndx < n_phdr; ++phdr_ndx) {
        if (gelf_getphdr(elfp, (int)phdr_ndx, &phdr) != &phdr) {
            report_anomaly_in_ctx(ctx, "failed to get program header "
                                  "%zd from on-disk ELF file: %s - %s",
                                  phdr_ndx, ctx->path, elf_errmsg(elf_errno()));
            return -1;
        }
        if (phdr.p_type == PT_DYNAMIC) {
            Elf_Data *data = elf_getdata_rawchunk(elfp, (off_t)phdr.p_offset,
                                                  phdr.p_filesz, ELF_T_DYN);
            if (data == NULL) {
                dlog(4,"Error getting DYNAMIC data for %s from offset "
                     "%#lx: %s",
                     ctx->path, phdr.p_offset, elf_errmsg(elf_errno()));
                return -1;
            }

            GElf_Dyn dyn;
            int dyn_ndx;
            int n_dyn = (int)(phdr.p_filesz / sizeof(ElfW(Dyn)));
            for (dyn_ndx = 0; dyn_ndx < n_dyn; ++dyn_ndx) {
                if (gelf_getdyn(data, dyn_ndx, &dyn) != &dyn) {
                    dlog(4,"Error getting DYNAMIC entry %d for %s: %s",
                         dyn_ndx, ctx->path, elf_errmsg(elf_errno()));
                    return -1;
                }
                if (dyn.d_tag == DT_NULL) {
                    break;
                }

                switch (dyn.d_tag) {
                case DT_RELA:
                    rela_addr = dyn.d_un.d_val;
                    break;
                case DT_RELASZ:
                    rela_sz = dyn.d_un.d_val;
                    break;
                case DT_JMPREL:
                    jmprel_addr = dyn.d_un.d_val;
                    break;
                case DT_PLTRELSZ:
                    jmprel_sz = dyn.d_un.d_val;
                    break;
                default:
                    break;
                }
            }
        }
    }

    if (ehdr->e_type == ET_EXEC) {
        rela_addr -= ctx->base_address;
        jmprel_addr -= ctx->base_address;
    }

    /* The type coercions for both calls to elf_getdata_rawchunk are because the data we're
       after is at some address in the chunk, but this function expresses the offset into a
       buffer as an int64_t. */
    Elf_Data *rela = elf_getdata_rawchunk(elfp,
                                          (int64_t)rela_addr, rela_sz, ELF_T_RELA);
    if (rela == NULL) {
        dlog(4,"Error getting RELA data for %s from address %#lx, offset "
             "from header %#lx", ctx->path, rela_addr,
             rela_addr - ctx->base_address);
        return -1;
    }

    Elf_Data *jmprel = elf_getdata_rawchunk(elfp,
                                            (int64_t)jmprel_addr, jmprel_sz, ELF_T_RELA);
    if (jmprel == NULL) {
        dlog(4,"Error getting JMPREL data for %s from address %#lx, offset "
             "from header %#lx", ctx->path, jmprel_addr,
             jmprel_addr - ctx->base_address);
        return -1;
    }

    int rela_limit = (int)(rela_sz / sizeof(Elf64_Rela));
    get_rela_min_max_got_offsets(rela, rela_limit,
                                 minimum_got_virtual_offset, maximum_got_virtual_offset);
    rela_limit = (int)(jmprel_sz / sizeof(Elf64_Rela));
    get_rela_min_max_got_offsets(jmprel, rela_limit,
                                 minimum_got_virtual_offset, maximum_got_virtual_offset);

    return 0;
}

static int parse_on_disk_elf(elf_context *ctx)
{
    int fd = open(ctx->path, O_RDONLY), res = TRUE;

    if (fd < 0) {
        report_anomaly_in_ctx(ctx, "on-disk ELF file not found: %s",
                              ctx->path);
        return FALSE;
    }

    Elf *elfp;
    if ((elfp = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
        report_anomaly_in_ctx(ctx, "failed to read on-disk ELF file: %s - %s",
                              ctx->path, elf_errmsg(elf_errno()));
        close(fd);
        return FALSE;
    }

    Elf_Kind ek;
    if ((ek = elf_kind(elfp)) != ELF_K_ELF) {
        report_anomaly_in_ctx(ctx, "Non-ELF file found where on-disk "
                              "ELF file expected: %s - elf_kind %d",
                              ctx->path, ek);
        res = FALSE;
        goto parse_on_disk_elf_cleanup;
    }

    GElf_Ehdr ehdr;
    if (gelf_getehdr(elfp, &ehdr) == NULL) {
        report_anomaly_in_ctx(ctx, "failed to get ehdr from on-disk ELF file: %s - %s",
                              ctx->path, elf_errmsg(elf_errno()));
        res = FALSE;
        goto parse_on_disk_elf_cleanup;
    }

    if (on_disk_elf_matches_ctx(&ehdr, elfp, fd, ctx) != TRUE) {
        res = FALSE;
        goto parse_on_disk_elf_cleanup;
    }

    size_t n_phdr = 0;
    if (elf_getphdrnum(elfp, &n_phdr) != 0) {
        report_anomaly_in_ctx(ctx, "failed to get program header count from on-disk ELF file: %s - %s",
                              ctx->path, elf_errmsg(elf_errno()));
        res = FALSE;
        goto parse_on_disk_elf_cleanup;
    }

    // This is predicated on the assumption of one contiguous GOT.
    uint64_t minimum_got_virtual_offset = 0;
    uint64_t maximum_got_virtual_offset = 0;
    get_got_virtual_offset_bounds(ctx, elfp, &ehdr, n_phdr,
                                  &minimum_got_virtual_offset,
                                  &maximum_got_virtual_offset);
    if (minimum_got_virtual_offset == 0
            || maximum_got_virtual_offset == 0) {
        report_anomaly_in_ctx(ctx, "Failed to identify the virtual "
                              "address bounds of the on-disk GOT in %s: found min %#lx, "
                              "max %#lx",
                              ctx->path, minimum_got_virtual_offset,
                              maximum_got_virtual_offset);
        res = FALSE;
    }
#define GOT_ENTRY_SZ 8
#ifdef DEBUG
    printf("Bounds of on-disk GOT: %#016lx - %#016lx\n",
           minimum_got_virtual_offset,
           maximum_got_virtual_offset + GOT_ENTRY_SZ);
#endif
    // NOTE: for an ET_EXEC ELF object, the offset will be an absolute
    // virtual address. For ET_DYN it will be a virtual address offset
    // from the start of the ELF header. This becomes important when we
    // appraise the GOT later to see if it contains the same value as
    // on-disk.

    size_t i;
    GElf_Phdr phdr;
    for (i = 0; i < n_phdr; ++i) {
        if (gelf_getphdr(elfp, (int)i, &phdr) != &phdr) {
            report_anomaly_in_ctx(ctx, "failed to get program header %zd from on-disk ELF file: %s - %s",
                                  i, ctx->path, elf_errmsg(elf_errno()));
            res = FALSE;
            goto parse_on_disk_elf_cleanup;
        }
        if (phdr.p_type == PT_LOAD) {
            Elf64_Addr segment_start = phdr.p_vaddr;
            Elf64_Addr segment_end = phdr.p_vaddr + phdr.p_memsz;
            if (minimum_got_virtual_offset >= segment_start
                    && minimum_got_virtual_offset < segment_end) {
                // TODO ideally handle the case where the GOT spans segments?

                uint64_t segment_offset = minimum_got_virtual_offset
                                          - segment_start;

                // Account for the last GOT entry by extending past the
                // maximum GOT offset.
                size_t buffer_sz = (maximum_got_virtual_offset
                                    - minimum_got_virtual_offset) + GOT_ENTRY_SZ;
                uint64_t file_offset = phdr.p_offset + segment_offset;

                // Often the segment is specified to have a larger space
                // in memory than in the file, implying the remainder
                // should be zero-filled. Check to see if we're crossing
                // that boundary, and use calloc to implicitly
                // zero-fill.
                size_t bytes_to_read = buffer_sz;
                uint64_t *got_buffer = calloc(1, buffer_sz);
                if ((long unsigned int)(segment_offset + bytes_to_read) > phdr.p_filesz) {
                    bytes_to_read = (size_t)(phdr.p_filesz - segment_offset);
                }

                ssize_t bytes_read = pread(fd, got_buffer, bytes_to_read,
                                           (off_t)file_offset);
                if (bytes_read != (ssize_t)bytes_to_read) {
                    report_anomaly_in_ctx(ctx, "Failed to read GOT from disk "
                                          "for %s: got %zd bytes out of %zd: %s",
                                          ctx->path, bytes_read, bytes_to_read,
                                          strerror(errno));
                    free(got_buffer);
                    res = FALSE;
                    goto parse_on_disk_elf_cleanup;
                }
                // Assume we got the whole GOT in one go.
                ctx->on_disk_got.got = got_buffer;
                ctx->on_disk_got.sz = buffer_sz;
                ctx->on_disk_got.vaddr = minimum_got_virtual_offset;
                break;
            }
        }
    }

#ifdef DEBUG_ON_DISK_GOT
    puts("On-disk GOT:");
    uint64_t *p;
    ptrdiff_t bytes_walked = 0;
    for (p = ctx->on_disk_got.got;
            (bytes_walked = PTR_DIFF(p, ctx->on_disk_got.got)) < (ptrdiff_t) ctx->on_disk_got.sz;
            ++p) {
        printf("  %#016tx : %#016lx\n",
               ctx->on_disk_got.vaddr + bytes_walked,
               *p);
    }
#endif

parse_on_disk_elf_cleanup:
    elf_end(elfp);
    close(fd);
    return res;
}

/* Parse the ELF object in the provided buffer. */
static elf_context *scan_elf_object(file_mapping_buffer *mb)
{
    int err;
#ifdef DEBUG
    printf("Scanning ELF object at %#lx mapped from %s\n",
           mb->start, mb->path);
#endif
    elf_context *ctx = calloc(1, sizeof(elf_context));
    if (!ctx) {
        dlog(4, "Unable to allocate memory for the elf context");
        return NULL;
    }

    ctx->path = mb->path;
    ctx->base_address = mb->start;
    ctx->buf = mb->buf;
    ctx->sz = mb->sz;

    // Verify against disk before modifying the memory
    if(parse_on_disk_elf(ctx) == FALSE) {
        dlog(4, "Unable to parse the on disk ELF");
        free(ctx);
        return NULL;
    }

    // The ELF header still has the settings for the section header
    // table even though it wasn't loaded, and libelf reads those
    // fields and tries to read the section header table, so zero
    // those fields out so libelf doesn't go reading bad memory.
    err = zero_out_sht_fields(mb->buf);
    if (err < 0) {
        goto fail_get_elf;
    }

    Elf *elfp = elf_memory(mb->buf, mb->sz);
    if (elfp == NULL) {
        dlog(4,"Failed to get ELF handle for %s: %s",
             mb->path, elf_errmsg(elf_errno()));
        goto fail_get_elf;
    }
    ctx->elfp = elfp;

    Elf_Kind ek;
    if ((ek = elf_kind(elfp)) != ELF_K_ELF) {
        dlog(4,"Non-ELF file found for %s: %d",
             mb->path, ek);
        goto fail_scan_elf;
    }

    if (gelf_getehdr(elfp, &ctx->ehdr) == NULL) {
        dlog(4,"getehdr() failed: %s", elf_errmsg(elf_errno()));
        goto fail_scan_elf;
    }

    if (ctx->ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        report_anomaly("ELF object for %s is not 64-bit. Only "
                       "64-bit ELF objects are supported at this time\nFAILED",
                       ctx->path);
        goto fail_scan_elf;
    }

    size_t n_phdr = 0;
    if (elf_getphdrnum(elfp, &n_phdr) != 0) {
        dlog(4,"elf_getphdrnum() failed: %s", elf_errmsg(elf_errno()));
        goto fail_scan_elf;
    }

    size_t i;
    GElf_Phdr phdr;
    for (i = 0; i < n_phdr; ++i) {
        if (gelf_getphdr(elfp, (int)i, &phdr) != &phdr) {
            dlog(4,"elf_getphdr() failed: %s", elf_errmsg(elf_errno()));
            goto fail_scan_elf;
        }
        if (phdr.p_type == PT_DYNAMIC) {
#ifdef DEBUG
            printf("DYNAMIC segment: offset: %#lx, vaddr: %#lx, paddr: %#lx, memsz: %#lx\n",
                   phdr.p_offset, phdr.p_vaddr, phdr.p_paddr, phdr.p_memsz);
#endif
            if (ctx->dynamic_address) {
                dlog(4,"multiple DYNAMIC segments found for %s, ignoring extras",
                     ctx->path);
            } else {
                if (parse_dynamic(elfp, ctx, &phdr) < 0) {
                    goto fail_scan_elf;
                }
            }
        }
    }

    if (ctx->dynamic_address == 0) {
#ifdef DEBUG
        printf("No PT_DYNAMIC program header found for %s, statically "
               "linked?", ctx->path);
#endif
        goto fail_scan_elf;
    }

    return ctx;

fail_scan_elf:
    elf_end(elfp);
fail_get_elf:
    free(ctx);
    return NULL;
}

static elf_context *scan_vdso(file_mapping_buffer *mb)
{
#ifdef DEBUG
    printf("Scanning VDSO ELF object at %#lx mapped from %s\n",
           mb->start, mb->path);
#endif
    elf_context *ctx = calloc(1, sizeof(elf_context));
    if (!ctx) {
        dlog(4, "Unable to allocate memory for an elf context");
        return NULL;
    }

    ctx->path = mb->path;
    ctx->base_address = mb->start;
    ctx->buf = mb->buf;
    ctx->sz = mb->sz;

    Elf *elfp = elf_memory(mb->buf, mb->sz);
    if (elfp == NULL) {
        dlog(4,"Failed to get ELF handle for %s: %s",
             mb->path, elf_errmsg(elf_errno()));
        free(ctx);
        return NULL;
    }
    ctx->elfp = elfp;

    Elf_Kind ek;
    if ((ek = elf_kind(elfp)) != ELF_K_ELF) {
        dlog(4,"Non-ELF file found for %s: %d",
             mb->path, ek);
        goto fail_scan_vdso;
    }

    if (gelf_getehdr(elfp, &ctx->ehdr) == NULL) {
        dlog(4,"getehdr() failed: %s", elf_errmsg(elf_errno()));
        goto fail_scan_vdso;
    }

    size_t n_phdr = 0;
    if (elf_getphdrnum(elfp, &n_phdr) != 0) {
        dlog(4,"elf_getphdrnum() failed: %s", elf_errmsg(elf_errno()));
        goto fail_scan_vdso;
    }

    // All of the virtual addresses in the VDSO are wonky. It looks like
    // they have a mask of 0xffffffffff700000 set on them. rtld appears
    // to handle this by subtracting the PT_LOAD p_vaddr from all vaddrs
    // to get an offset that gets added to the mapping start.
    size_t i;
    GElf_Phdr phdr;
    for (i = 0; i < n_phdr; ++i) {
        if (gelf_getphdr(elfp, (int)i, &phdr) != &phdr) {
            dlog(4,"elf_getphdr() failed: %s", elf_errmsg(elf_errno()));
            goto fail_scan_vdso;
        }
        if (phdr.p_type == PT_LOAD) {
            ctx->vaddr_adjustment = phdr.p_vaddr;
        } else if (phdr.p_type == PT_DYNAMIC) {
#ifdef DEBUG
            printf("DYNAMIC segment: offset: %#lx, vaddr: %#lx, paddr: %#lx, memsz: %#lx\n",
                   phdr.p_offset, phdr.p_vaddr, phdr.p_paddr, phdr.p_memsz);
#endif
            if (ctx->dynamic_address) {
                dlog(4,"multiple DYNAMIC segments found for %s, ignoring extras",
                     ctx->path);
            } else {
                ctx->dynamic_address = phdr.p_vaddr - ctx->vaddr_adjustment
                                       + ctx->base_address;
                if (parse_vdso_dynamic(elfp, ctx, &phdr) < 0) {
                    goto fail_scan_vdso;
                }
            }
        }
    }

    return ctx;

fail_scan_vdso:
    elf_end(elfp);
    free(ctx);
    return NULL;
}

static elf_context *ctx_for_address(
    uint64_t address,
    GList *elf_contexts)
{
    GList *p;
    for (p = elf_contexts; p && p->data; p = p->next) {
        elf_context *ctx = (elf_context *)p->data;
        if (address >= ctx->base_address &&
                address < ctx->base_address + ctx->sz) {
            return ctx;
        }
    }
    return NULL;
}

static void add_matching_symbols(
    got_entry *entry,
    elf_context *ctx,
    uint64_t value)
{
    GSList *matches = NULL;
    if (ctx->ehdr.e_type != ET_EXEC) {
        value -= ctx->base_address;
    }

    size_t sym_ndx;
    for (sym_ndx = 0; sym_ndx < ctx->symtab_sz / ctx->syment_sz; ++sym_ndx) {
        GElf_Sym sym;

        if (gelf_getsym(ctx->symtab, (int)sym_ndx, &sym) != &sym) {
            dlog(4,"Failed to get symbol %zd for %s: %s", sym_ndx,
                 ctx->path, elf_errmsg(elf_errno()));
        } else if (sym.st_value - ctx->vaddr_adjustment == value) {
            got_symbol_match *match = malloc(
                                          sizeof(got_symbol_match));

            if (!match) {
                dlog(4, "Failed to allocate memory for match object for symbol %zd for %s: %s",
                     sym_ndx, ctx->path, elf_errmsg(elf_errno()));
                continue;
            }

            match->name = ctx->strtab + sym.st_name;
            if (fill_in_symbol_version_info((int)sym_ndx, sym.st_shndx, ctx,
                                            &match->version,
                                            &match->hidden,
                                            NULL) < 0) {
                match->version = NULL;
                match->hidden = 0;
            }
            matches = g_slist_prepend(matches, match);
        }
    }
    entry->matching_symbols = g_slist_reverse(matches);
}

static uint64_t *get_pointer_to_original_got_value(
    uint64_t r_offset,
    elf_context *ctx)
{
    if (ctx->on_disk_got.got == NULL || ctx->on_disk_got.vaddr == 0) {
        return NULL;
    }

    uint64_t got_offset = r_offset - ctx->on_disk_got.vaddr;
    if (got_offset > ctx->on_disk_got.sz) {
        report_anomaly_in_ctx(ctx, "Unable to retrieve original value "
                              "of GOT entry at %#lx: GOT entry offset exceeded the GOT "
                              "extracted from the on-disk file: GOT begins at %#lx, size %zd",
                              r_offset,
                              ctx->on_disk_got.vaddr,
                              ctx->on_disk_got.sz);
        return NULL;
    }

    uint64_t *ptr = ctx->on_disk_got.got
                    + (got_offset / sizeof(*ctx->on_disk_got.got));

    return ptr;
}

/* Gets the base load address of the executable ELF object from
 * /proc/<PID>/stat. This field is referred to as the startcode in
 * `man 5 proc`*/
static uint64_t get_executable_base_load_address(const char *pid)
{
    uint64_t addr;
    char path[PATH_MAX] = "/proc/";

    strncat(path, pid, (size_t)g_num_digits_pid);
    strncat(path, "/stat", 6);

    char* line = NULL;
    size_t line_sz = 0;

    FILE *fp = fopen(path, "r");
    if(fp == NULL) {
        dlog(4, "Can't open /proc/%s/stat!\n", pid);
        return 0;
    }

    ssize_t chars_read = getline(&line, &line_sz, fp);
    if (chars_read < 0) {
        report_anomaly("Failed to read /proc/<PID>/stat");
        fclose(fp);
        return 0;
    }

    // The second stat entry, comm, may contain spaces or parens but
    // should end with a closing paren. Therefore the second entry ends
    // with that closing paren.
    char *p = strrchr(line, ')');
    if (*p != ')') {
        report_anomaly("Contents of the stat file for PID %s did not match expectations: failed "
                       "to find closing paren for executable name/comm entry\n",
                       pid);
        addr = 0;
        goto end;
    }

    ++p;
    int i = 2;
    for (; i < STAT_STARTCODE_INDEX; ++i) {
        p = strchr(p, ' ');
        if (*p != ' ') {
            report_anomaly("Contents of the stat file for PID %s did not match expectations: failed "
                           "to find closing paren for executable name/comm entry\n",
                           pid);
            addr = 0;
            goto end;
        }
        ++p;
    }
    char *end = strchr(p, ' ');
    *end = '\0';

    char *endptr = NULL;
    errno = 0;
    addr = strtoul(p, &endptr, 0);

    if (errno != 0) {
        report_anomaly("Contents of stat file for PID %s did not match expectations: failed "
                       "to parse startcode from %s\n", pid, p);
        addr = 0;
        goto end;
    }

    if (addr == 0) {
        report_anomaly("startcode parsed from \"%s\" was zero, "
                       "assuming kernel process\nFAILED", line);
        addr = 0;
    }

end:
    free(line);
    fclose(fp);

    return addr;
}

static char *get_executable_path(const char *pid)
{
    char path[PATH_MAX] = "/proc/";

    strncat(path, pid, (size_t)g_num_digits_pid);
    strncat(path, "/exe", 5);

    errno = 0;
    char *exe_path = realpath(path, NULL);
    if (errno == ENOENT) {
        char buff[PATH_MAX] = {0};
        errno = 0;
        ssize_t retval = readlink(path, buff, sizeof(buff));
        if (retval == -1) {
            dlog(4, "Error reading exe path from %s: %s\n",
                 path, strerror(errno));
            return NULL;
        }
        report_anomaly("The executable file used to launch the "
                       "process was deleted: '%s'", buff);
        /* Returns NULL on failure */
        return strdup(buff);
    } else if (!exe_path || errno) {
        int backup = errno;
        dlog(4, "Error resolving executable path %s: %s\n",
             path, strerror(errno));
        dlog(4, "Errno = %d\n", backup);
        dlog(4, "EINVAL = %d\n", ENOENT);
        return NULL;
    }

    return exe_path;
}

/* Find the address of any link_map node. */
static uint64_t find_link_map_address(GList *elf_contexts)
{
    GList *p = NULL;
    for (p = elf_contexts; p && p->data; p = p->next) {
        elf_context *ctx = (elf_context*)p->data;
        if (ctx->linkmap_address != 0) {
            return ctx->linkmap_address;
        }
    }
    return 0;
}


static char *get_interpreter_path(elf_context *ctx)
{
    size_t n_phdr = 0;
    if (elf_getphdrnum(ctx->elfp, &n_phdr) != 0) {
        dlog(4,"elf_getphdrnum() failed: %s", elf_errmsg(elf_errno()));
        return NULL;
    }

    GElf_Phdr phdr;
    char *interp = NULL;
    uint64_t offset = 0;
    size_t i;
    for (i = 0; i < n_phdr; ++i) {
        if (gelf_getphdr(ctx->elfp, (int)i, &phdr) != &phdr) {
            dlog(4,"elf_getphdr() failed: %s", elf_errmsg(elf_errno()));
            return interp;
        }
        if (phdr.p_type == PT_INTERP) {
            if (ctx->ehdr.e_type != ET_EXEC) {
                offset += ctx->base_address;
            }
            offset += phdr.p_vaddr;
            interp = ctx->buf + offset - ctx->base_address;
            size_t sz = strnlen(interp, phdr.p_memsz);
            interp = strndup(interp, sz);

            /* Yes, you could just fall through to the next line which would return NULL,
             * but this gives more information about the failure and protects the debug statement
             * from garbage values */
            if (!interp) {
                dlog(4, "Unable to allocate buffer for the interpreter path\n");
                return NULL;
            }
#ifdef DEBUG
            printf("%s PT_INTERP at %p is %s: offset: %#lx, vaddr: %#lx, "
                   "paddr: %#lx, memsz: %#lx\n",
                   ctx->path, interp, interp,
                   phdr.p_offset, phdr.p_vaddr, phdr.p_paddr, phdr.p_memsz);
#endif
            return interp;
        }
    }

    dlog(4,"Failed to find PT_INTERP program header");
    return interp;
}



static GElf_Sym *get_dynsym(elf_context *ctx, const char *sym_name)
{
    if (!ctx->symtab || !ctx->symtab_sz || !ctx->syment_sz || !ctx->strtab) {
        dlog(4, "Could not search for symbol %s because ELF context for "
             "%s was missing symtab information", sym_name, ctx->path);
        return NULL;
    }

    GElf_Sym *sym = malloc(sizeof(GElf_Sym));

    if (!sym) {
        dlog(4, "Unable to allocate memory for symbol");
        goto error;
    }

    int i;
    for (i = 0; (size_t) i < ctx->symtab_sz / ctx->syment_sz; ++i) {
        if (gelf_getsym(ctx->symtab, i, sym) != sym) {
            dlog(4, "Failed to get symbol %d for %s: %s", i,
                 ctx->path, elf_errmsg(elf_errno()));
        } else if (strcmp(sym_name, ctx->strtab + sym->st_name) == 0) {
            return sym;
        }
    }

error:
    dlog(4, "Failed to find symbol %s in the dynamic symbol table of %s",
         sym_name, ctx->path);
    free(sym);
    return NULL;
}

/*
 * Only used from expermiental code that is not compiled by default
 */
static uint64_t guess_link_map_address(GList *elf_contexts)
{
    uint64_t address = 0;

    // Assume the executable ELF context has already been moved to the
    // front.
    elf_context *exe_ctx = elf_contexts->data;

    char *interp = get_interpreter_path(exe_ctx);
    if (interp == NULL) {
        return address;
    }
    char *absolute_path = realpath(interp, NULL);
    if (absolute_path == NULL) {
        warn("Failed to resolve interpreter path");
        return address;
    }
    free(interp);

#ifdef DEBUG
    printf("Real path of interpreter: %s\n", absolute_path);
#endif

    // Find the context for the interpreter
    GList *p = NULL;
    for (p = elf_contexts; p && p->data; p = p->next) {
        elf_context *ctx = (elf_context*)p->data;
        if (strcmp(ctx->path, absolute_path) == 0) {
            // TODO figure out a general, reliable way to find the address
            // of the link_map on most platforms.
            //
            // On a CentOS 7 VM it's consistently at offset 0x221350
            // from the start of the ELF header of /usr/lib64/ld-2.17.so.
            // Looking through the symbol table, this happend to line up
            // with the value of the symbol "_end" and happens to be 0x30
            // greater than the value of the symbol "_r_debug", which is
            // in the dynamic symbol table. It looks like _r_debug is
            // followed by audit_list_string and then the link_map.
            GElf_Sym *sym = get_dynsym(ctx, "_r_debug");
            if (sym == NULL) {
                return address;
            }

#define OFFSET_TO_LINK_MAP_FROM__R_DEBUG 0x30
            uint64_t link_map_offset = sym->st_value +
                                       OFFSET_TO_LINK_MAP_FROM__R_DEBUG;
            address = ctx->base_address + link_map_offset;

#ifdef DEBUG
            printf("Guessed link_map offset %#lx, address %#lx\n",
                   link_map_offset, address);
#endif
            free(absolute_path);
            free(sym);
            return address;
        }
    }

    dlog(4,"Failed to find interpreter ELF context");
    free(absolute_path);
    return address;
}


/* Unlinks a GList node by making the previous and next nodes point to
 * each other.
 */
static void unlink_glist_node(GList *node)
{
    GList *prev = node->prev;
    GList *next = node->next;
    node->prev = NULL;
    node->next = NULL;
    if (prev) {
        prev->next = next;
    }
    if (next) {
        next->prev = prev;
    }
}

/* Takes a GList node, assumed to be unlinked, and a reference to a node
 * in a GList and inserts the unlinked node into the list immediately
 * after the referenced node.
 */
static void insert_glist_node_after(GList *to_insert, GList *predecessor)
{
    assert(to_insert->next == NULL);
    assert(to_insert->prev == NULL);
    to_insert->next = predecessor->next;

    if (to_insert->next != NULL) {
        to_insert->next->prev = to_insert;
    }
    to_insert->prev = predecessor;
    predecessor->next = to_insert;
}

static GList *find_ctx_with_base_addr(GList *p, uint64_t addr)
{
    GList *iter;
    for (iter = p; iter; iter = iter->next) {
        if (iter->data != NULL) {
            elf_context *ctx = (elf_context*)iter->data;
            if (ctx->base_address == addr) {
                return iter;
            }
        } else {
            dlog(4, "Null data in find_ctx_with_base_addr\n");
        }
    }
    return NULL;
}

/* Finds the elf_context whose base load address matches the provided
 * one and moves it to the front of the elf_context list. */
static int move_exe_context_to_front(
    GList **list,
    uint64_t exe_base_load_addr)
{
    GList *p = find_ctx_with_base_addr(*list, exe_base_load_addr);
    if (p == NULL) {
        report_anomaly("No mapped ELF object started at the executable "
                       "start address %" PRIu64 " - the original executable was unmapped!", exe_base_load_addr);
        return -1;
    }

    if (p->prev != NULL) {
        unlink_glist_node(p);
        p->next = *list;
        (*list)->prev = p;
        *list = p;
    }
    return 0;
}

static int verify_executable_link_map_entry(
    GSList *linkmap_list,
    GList *elf_contexts)
{
    int status = 0;
    link_map_wrapper *wrapper = linkmap_list->data;
    struct link_map linkmap = wrapper->link_map;

    if (strncmp(linkmap.l_name, "", 1) != 0) {
        report_anomaly("Executable link_map entry had non-empty file name: "
                       "%s", linkmap.l_name);
    }

    // Assume that the first elf_object_context is for the executable
    elf_context *ctx = elf_contexts->data;
    if (ctx->ehdr.e_type == ET_EXEC) {
        if (linkmap.l_addr != 0) {
            report_anomaly("Executable link_map entry had non-zero base "
                           "load address, l_addr: %#lx", linkmap.l_addr);
            status = -1;
        }
    } else {
        if (linkmap.l_addr != ctx->base_address) {
            report_anomaly("Executable link_map entry base load "
                           "address (%#lx) did not match the ELF object's base "
                           "load address (%#lx)", linkmap.l_addr, ctx->base_address);
            status = -1;
        }
    }

    if ((uint64_t) linkmap.l_ld != ctx->dynamic_address) {
        report_anomaly("Executable link_map entry dynamic "
                       "address (%p) did not match the ELF object's dynamic "
                       "address (%#lx)", linkmap.l_ld, ctx->dynamic_address);
        status = -1;
    }

    // TODO further validation of the executable link_map entry?
    //  - file path in /proc/<PID>/exe matches elf_context path?
    //  - file contents match what is mapped?
    //  - entry point address (adjusted for base load address) matches
    //  AT_ENTRY aux vector entry
    //      - at least on a CentOS 7 VM, even if a process modifies the
    //      memory for its auxiliary vector, the information in
    //      /proc/<PID>/auxv remains unchanged
    //  - verify that the AT_PHDR aux vector entry matches the start of the
    //      program header table

#ifdef DEBUG
    puts("Verified executable link_map entry");
#endif

    return status;
}

static int verify_vdso_link_map_entry(GSList *linkmap_list, const char *pid_string)
{
    int status = 0;

    if(strnlen(pid_string, (size_t)g_num_digits_pid + 1) > (size_t) g_num_digits_pid) {
        report_anomaly("Given invalid PID");
        return -1;
    }

    if (linkmap_list->next == NULL) {
        report_anomaly("link_map only had 1 entry: expected VDSO entry and others");
        return -1;
    }

    // l_name should be ""
    link_map_wrapper *wrapper = linkmap_list->next->data;
    if (wrapper->link_map.l_name == NULL) {
        report_anomaly("VDSO link_map entry had NULL l_name");
        status = -1;
    }
    /* This check seems to be an overfit that only applies to CentOS.
     * For example, in Ubuntu it seems that vdso link map entries can
     * have non-null l_name fields.*/
    /*else if (*wrapper->link_map.l_name != '\0')
    {
        report_anomaly("VDSO link_map entry had non-empty l_name: %s",
            wrapper->link_map.l_name);
        status = -1;
    }*/

    memory_mapping *vdso_mapping = get_mapping(pid_string, "[vdso]");
    if (vdso_mapping == NULL) {
        report_anomaly("Failed to find [vdso] mapping");
        status = -1;
    } else {
        // Match rtld's logic for computing l_ld and l_addr (get offsets
        // and vaddrs from program headers).
        mapping_group *grp = create_mapping_group(vdso_mapping);
        file_mapping_buffer *mb = create_file_mapping_buffer(grp);
        Elf *elfp = elf_memory(mb->buf, mb->sz);
        if (elfp == NULL) {
            dlog(4,"Failed to get ELF handle for %s: %s",
                 mb->path, elf_errmsg(elf_errno()));
            status = -1;
            goto verify_vdso_link_map_entry_cleanup;
        }

        size_t n_phdr = 0;
        if (elf_getphdrnum(elfp, &n_phdr) != 0) {
            dlog(4,"elf_getphdrnum() failed: %s", elf_errmsg(elf_errno()));
            elf_end(elfp);
            status = -1;
            goto verify_vdso_link_map_entry_cleanup;
        }

        uint64_t expected_l_addr = 0;
        uint64_t dynamic_address = 0;
        int pt_dyn = 0, pt_load = 0;
        size_t i;
        GElf_Phdr *phdr = malloc(sizeof(GElf_Phdr));

        if (!phdr) {
            dlog(4, "Unable to allocate buffer for Program Header");
            elf_end(elfp);
            status = -1;
            goto verify_vdso_link_map_entry_cleanup;
        }

        for (i = 0; i < n_phdr; ++i) {
            if (gelf_getphdr(elfp, (int)i, phdr) != phdr) {
                dlog(4,"elf_getphdr() failed: %s", elf_errmsg(elf_errno()));
                free(phdr);
                elf_end(elfp);
                status = -1;
                goto verify_vdso_link_map_entry_cleanup;
            }
            if (phdr->p_type == PT_DYNAMIC) {
                if (pt_dyn) {
                    dlog(4,"VDSO has multiple PT_DYNAMIC program headers");
                }
                dynamic_address = vdso_mapping->start + phdr->p_offset;
                pt_dyn = 1;
            } else if (phdr->p_type == PT_LOAD) {
                if (pt_load) {
                    dlog(4,"VDSO has multiple PT_LOAD program headers");
                }
                expected_l_addr = -phdr->p_vaddr;
                pt_load = 1;
            }
        }
        free(phdr);
        elf_end(elfp);

        /* Because PT_LOAD segments van have a p_vaddr value of zero,
             * merely checking that the value remains zero does not work */
        if (!pt_dyn || !pt_load) {
            dlog(4,"Failed to parse VDSO program headers");
            status = -1;
            goto verify_vdso_link_map_entry_cleanup;
        }

        expected_l_addr += vdso_mapping->start;
        if (wrapper->link_map.l_addr != expected_l_addr) {
            report_anomaly("VDSO link_map entry had unexpected l_addr "
                           "%#lx instead of %#lx", wrapper->link_map.l_addr,
                           expected_l_addr);
            status = -1;
        }

        if ((uint64_t) wrapper->link_map.l_ld != dynamic_address) {
            report_anomaly("VDSO link_map entry had unexpected l_ld "
                           "%#lx instead of %#lx",
                           wrapper->link_map.l_ld, dynamic_address);
            status = -1;
        }

#ifdef DEBUG
        printf("VDSO verification:\n"
               "    l_addr %#lx matches %#lx\n"
               "    l_ld %#lx matches %#lx\n",
               wrapper->link_map.l_addr,
               expected_l_addr,
               (uint64_t) wrapper->link_map.l_ld,
               dynamic_address);
#endif

verify_vdso_link_map_entry_cleanup:
        free_file_mapping_buffer(mb, GINT_TO_POINTER(TRUE));
        free_mapping_group(grp);
    }

#ifdef DEBUG
    if(!status) {
        puts("Verified VDSO link_map entry");
    }
#endif

    return status;
}

static void verify_ctx_link_match(
    elf_context *ctx,
    link_map_wrapper *wrapper)
{
    if (ctx->dynamic_address !=
            (uint64_t) wrapper->link_map.l_ld) {
        report_anomaly_in_ctx(ctx, "link_map dynamic address "
                              "(%p) did not match actual dynamic address "
                              "%#lx", wrapper->link_map.l_ld, ctx->dynamic_address);
    }

    if (ctx->linkmap_address != 0 &&
            ctx->linkmap_address != wrapper->address) {
        report_anomaly_in_ctx(ctx, "ELF link_map reference "
                              "(%#lx) did not match actual link_map address "
                              "%#lx", ctx->linkmap_address, wrapper->address);
    }

    // TODO - what about when l_name is just the file name? Where does
    // rtld store the full path? It dumps it with LD_DEBUG, so it has it
    // somewhere.
    char *buf = realpath(wrapper->link_map.l_name, NULL);
    if (buf == NULL) {
        warn("Failed to resolve link_map path '%s', could not confirm "
             "it matches executable file mapping path '%s'",
             wrapper->link_map.l_name,
             ctx->path);
    } else if (strcmp(buf, ctx->path) != 0) {
        report_anomaly("Disagreement between link_map path '%s' "
                       "(resolved to '%s') and executable file mapping path '%s'",
                       wrapper->link_map.l_name, buf, ctx->path);
    }
    free(buf);
}


static int reorder_contexts(
    GList *elf_contexts,
    GSList *linkmap_list)
{
    int status = 0;

    // Skip executable and VDSO entries
    GSList *link_p = linkmap_list->next->next;
    elf_contexts = elf_contexts->next;

    for (; link_p && elf_contexts && link_p->data && elf_contexts->data;
            link_p = link_p->next) {
        link_map_wrapper *wrapper = (link_map_wrapper *)link_p->data;

        GList *ctx_p = find_ctx_with_base_addr(
                           elf_contexts,
                           wrapper->link_map.l_addr);
        if (ctx_p == NULL) {
            report_anomaly("The link_map entry for '%s' with l_addr %#lx "
                           "had no corresponding file mapping!",
                           wrapper->link_map.l_name, wrapper->link_map.l_addr);
            status = -1;
            continue;
        }

        elf_context *ctx = (elf_context *)ctx_p->data;
        if(ctx) {
            verify_ctx_link_match(ctx, wrapper);

#ifdef DEBUG
            printf("Matched link_map entry for '%s', l_addr %#lx "
                   "with mapping for %s at %#lx\n",
                   wrapper->link_map.l_name, wrapper->link_map.l_addr,
                   ctx->path, ctx->base_address);
#endif
        }

        if (ctx_p != elf_contexts) {
            unlink_glist_node(ctx_p);
            insert_glist_node_after(ctx_p, elf_contexts->prev);
        }

        elf_contexts = ctx_p->next;
    }

    if (link_p != NULL) {
        for (; link_p && link_p->data; link_p = link_p->next) {
            link_map_wrapper *wrapper = (link_map_wrapper *)link_p->data;
            report_anomaly("No executable file mapping for link_map "
                           "entry with l_name %s, base address %#lx, dynamic "
                           "section address %p",
                           wrapper->link_map.l_name,
                           wrapper->link_map.l_addr,
                           wrapper->link_map.l_ld);
        }
    }

    if (elf_contexts != NULL) {
        for (; elf_contexts && elf_contexts->data; elf_contexts = elf_contexts->next) {
            elf_context *ctx = (elf_context *)elf_contexts->data;
            report_anomaly("No link_map entry for executable file mapping "
                           "of %s at base address %#lx",
                           ctx->path,
                           ctx->base_address);
        }
    }

    return status;
}

static char *r_type_to_string(uint64_t r_type)
{
    switch (r_type) {
    case R_X86_64_JUMP_SLOT:
        return "R_X86_64_JUMP_SLOT";
    case R_X86_64_GLOB_DAT:
        return "R_X86_64_GLOB_DAT";
    default:
        return "unrecognized r_type";
    }
}

static char *st_bind_to_string(unsigned char st_bind)
{
    switch (st_bind) {
    case STB_LOCAL:
        return "STB_LOCAL";
    case STB_GLOBAL:
        return "STB_GLOBAL";
    case STB_WEAK:
        return "STB_WEAK";
    case STB_GNU_UNIQUE:
        return "STB_GNU_UNIQUE";
    default:
        return "Unrecognized st_bind";
    }
}

static char *st_type_to_string(unsigned char st_type)
{
    switch (st_type) {
    case STT_NOTYPE:
        return "STT_NOTYPE";
    case STT_OBJECT:
        return "STT_OBJECT";
    case STT_FUNC:
        return "STT_FUNC";
    case STT_GNU_IFUNC:
        return "STT_GNU_IFUNC";
    case STT_SECTION:
        return "STT_SECTION";
    case STT_FILE:
        return "STT_FILE";
    default:
        return "Unrecognized st_type";
    }
}

static char *st_visibility_to_string(unsigned char st_visibility)
{
    switch (st_visibility) {
    case STV_DEFAULT:
        return "STV_DEFAULT";
    case STV_INTERNAL:
        return "STV_INTERNAL";
    case STV_HIDDEN:
        return "STV_HIDDEN";
    case STV_PROTECTED:
        return "STV_PROTECTED";
    default:
        return "unrecognized st_visibility";
    }
}


static void print_resolution(symbol_resolution *resolution)
{
    if (resolution->address == 0) {
        puts("  Failed to resolve symbol");
        return;
    }

    printf("  Expected symbol resolution:\n"
           "    address: %#lx\n"
           "    library: %s\n"
           "    version: %s\n"
           "    st_bind: %s\n"
           "    st_type: %s\n"
           "    st_visibility: %s\n"
           "    st_shndx: %hu\n",
           resolution->address,
           resolution->library,
           resolution->symbol_version,
           st_bind_to_string(
               ELF64_ST_BIND(resolution->st_info)),
           st_type_to_string(
               ELF64_ST_TYPE(resolution->st_info)),
           st_visibility_to_string(
               ELF64_ST_VISIBILITY(resolution->st_other)),
           resolution->st_shndx);
}

static void print_got_entry(got_entry *entry)
{
    printf("GOT entry at %#lx %s\n"
           "  r_type: %s\n"
           "  st_bind: %s\n"
           "  st_type: %s\n"
           "  contents: %#lx\n",
           entry->address,
           entry->symbol_name,
           r_type_to_string(entry->relocation_type),
           st_bind_to_string(ELF64_ST_BIND(entry->st_info)),
           st_type_to_string(ELF64_ST_TYPE(entry->st_info)),
           entry->contents);
    if (entry->pointer_to_original_contents) {
        printf("  original contents: %#lx\n",
               *(entry->pointer_to_original_contents));
    } else {
        puts("  original contents: (unknown)");
    }
    if (entry->symbol_version != NULL) {
        printf("  version needed: %s\n", entry->symbol_version);
    }
    if (entry->expected_library != NULL) {
        printf("  expected library: %s\n", entry->expected_library);
    }
    printf("  hidden: %hhu\n", entry->hidden);
    printf("  matching library: %s\n", entry->matching_library);
    if (entry->matching_symbols != NULL) {
        printf("  matching symbols:");
        GSList *tmp;
        for (tmp = entry->matching_symbols; tmp && tmp->data; tmp = tmp->next) {
            got_symbol_match *m = (got_symbol_match*)tmp->data;
            printf("\n    %s", m->name);
            if (m->version != NULL) {
                printf(" version %s", m->version);
            }
            if (m->hidden) {
                printf(" (hidden)");
            }
        }
        putchar('\n');
    }
}

static uint32_t gnu_hash(const uint8_t* name)
{
    uint32_t h = 5381;

    for (; *name; name++) {
        h = (h << 5) + h + *name;
    }

    return h;
}

static int bloom_filter_check(
    uint32_t sym_hash,
    uint32_t *hashtab)
{
    uint32_t bloom_size = hashtab[2];
    uint32_t bloom_shift = hashtab[3];
    bloom_t *bloom = (void*)&hashtab[4];


    bloom_t word = bloom[(sym_hash / ELFCLASS_BITS) % bloom_size];
    bloom_t mask = 0
                   | (bloom_t)1 << (sym_hash % ELFCLASS_BITS)
                   | (bloom_t)1 << ((sym_hash >> bloom_shift) % ELFCLASS_BITS);
    if ((word & mask) != mask) {
        return FALSE;
    }
    return TRUE;
}

static int attempt_resolve_symbol(
    const char *sym_name,
    int sym_ndx,
    got_entry *entry,
    GElf_Sym *sym,
    elf_context *ctx,
    uint64_t offset,
    symbol_resolution *resolution,
    symbol_resolution *weak_resolution)
{
#ifdef DEBUG_SYMBOL_RESOLUTION
    printf("Attempting to resolve symbol %s, found a match in %s\n", sym_name, ctx->path);
#endif
    if (sym->st_value != 0) {
        if (entry->relocation_type == R_X86_64_JUMP_SLOT
                && sym->st_shndx == SHN_UNDEF
                && ELF64_ST_TYPE(sym->st_info) == STT_FUNC
                && sym->st_size == 0) {
#ifdef DEBUG_SYMBOL_RESOLUTION
            puts("Skipping: function reference");
#endif
            return FALSE;
        }
        char *version = NULL;
        fill_in_symbol_version_info(
            sym_ndx,
            sym->st_shndx,
            ctx,
            &version,
            // It appears that the hidden flag doesn't matter for
            // dynamic linking, so it is ignored.
            NULL,
            NULL);

        uint64_t resolved_address = sym->st_value + offset - ctx->vaddr_adjustment;

        if (resolved_address == 0) {
#ifdef DEBUG_SYMBOL_RESOLUTION
            puts("Skipping: resolved to 0");
#endif
            return FALSE;
        }

        if (entry->symbol_version != NULL && version != NULL
                && strcmp(entry->symbol_version, version) != 0) {
#ifdef DEBUG_SYMBOL_RESOLUTION
            printf("Skipping: version mismatch: need %s found %s\n",
                   entry->symbol_version, version);
#endif
            return FALSE;
        }

        if (ELF64_ST_TYPE(sym->st_info) == STT_GNU_IFUNC) {
            // The address returned by the indirect function
            // should be stored in the GOT of this ELF object.
            // Look in the JMPREL table for an
            // R_X86_64_IRELATIVE entry with an addend that
            // adds to this symbol's address when added to the
            // base load address of the object. That JMPREL
            // entry's r_offset gives the GOT address or offset
            // to the GOT entry that holds the desired address.
            if (ctx->jmprel_sz > 0 && ctx->jmprel != NULL) {
                /* This may get flagged as dangerous, but I don't actually think there
                   are values that can make this conversion dangers due to the division */
                int rela_limit = (int)(ctx->jmprel_sz / sizeof(Elf64_Rela));
                GElf_Rela rela;
                int j = 0;
                for (j = 0; j < rela_limit; ++j) {
                    if (gelf_getrela(ctx->jmprel, j, &rela) != &rela) {
                        break;
                    }
                    int r_type = ELF64_R_TYPE(rela.r_info);
                    if (r_type == R_X86_64_IRELATIVE) {
#if DEBUG > 2
                        printf("Checking R_X86_64_IRELATIVE entry:\n"
                               "  sym->st_value: %#lx\n"
                               "  offset: %#lx\n"
                               "  ctx->vaddr_adjustment: %#lx\n"
                               "  rela.r_addend: %ld\n"
                               "  ctx-> base_address: %#lx\n",
                               sym->st_value,
                               offset,
                               ctx->vaddr_adjustment,
                               rela.r_addend,
                               ctx->base_address);
#endif
                        if (resolved_address == (uint64_t)(rela.r_addend) + ctx->base_address) {
                            resolved_address =
                                *(uint64_t *) (ctx->buf + rela.r_offset);
#ifdef DEBUG
                            printf("IFUNC match for %s, getting GOT "
                                   "value stored at %#lx: %#lx\n",
                                   sym_name,
                                   ctx->base_address + rela.r_offset,
                                   resolved_address);
#endif
                        }
                    }
                }
            }
        }

        if (ELF64_ST_BIND(sym->st_info) == STB_GLOBAL) {
            resolution->address = resolved_address;
            resolution->library = ctx->path;
            resolution->st_info = sym->st_info;
            resolution->st_other = sym->st_other;
            resolution->st_shndx = sym->st_shndx;
            resolution->symbol_version = version;
#ifdef DEBUG_SYMBOL_RESOLUTION
            printf("Resolved '%s' to path %s\n", sym_name,
                   ctx->path);
            print_got_entry(entry);
            print_resolution(resolution);
#endif
            return TRUE;
        } else if (ELF64_ST_BIND(sym->st_info) == STB_GNU_UNIQUE) {
            resolution->symbol_name = sym_name;
            resolution->address = resolved_address;
            resolution->library = ctx->path;
            resolution->st_info = sym->st_info;
            resolution->st_other = sym->st_other;
            resolution->st_shndx = sym->st_shndx;
            resolution->symbol_version = version;
#ifdef DEBUG_SYMBOL_RESOLUTION
            printf("Resolved '%s' to path %s\n", sym_name,
                   ctx->path);
            print_resolution(resolution);
#endif
            symbol_resolution *uniq =
                malloc(sizeof(symbol_resolution));
            if (!uniq) {
                dlog(4, "Unable to allocate memory for symbol reolution object");
                return FALSE;
            }

            memcpy(uniq, resolution,
                   sizeof(symbol_resolution));
            unique_symbol_resolutions =
                g_slist_prepend(
                    unique_symbol_resolutions, uniq);
            return TRUE;
        } else if (ELF64_ST_BIND(sym->st_info) == STB_WEAK &&
                   weak_resolution->address == 0) {
#if DEBUG >= 1
            printf("Weakly resolved '%s' to path %s\n", sym_name,
                   ctx->path);
#endif

            weak_resolution->address = resolved_address;
            weak_resolution->library = ctx->path;
            weak_resolution->st_info = sym->st_info;
            weak_resolution->st_other = sym->st_other;
            weak_resolution->st_shndx = sym->st_shndx;
            weak_resolution->symbol_version = version;
        }
#ifdef DEBUG_SYMBOL_RESOLUTION
        else {
            puts("Skipping");
            symbol_resolution tmp = {0};
            tmp.address = resolved_address;
            tmp.library = ctx->path;
            tmp.st_info = sym->st_info;
            tmp.st_other = sym->st_other;
            tmp.st_shndx = sym->st_shndx;
            tmp.symbol_version = version;
            print_resolution(&tmp);
        }
#endif
    } else {
#ifdef DEBUG_SYMBOL_RESOLUTION
        puts("Skipping: sym->st_value was zero");
#endif
    }

    return FALSE;
}

static void resolve_symbol_in_ctx(
    const char *sym_name,
    got_entry *entry,
    elf_context *ctx,
    symbol_resolution *resolution,
    symbol_resolution *weak_resolution)
{
    uint64_t offset = 0;

    if (ctx->ehdr.e_type != ET_EXEC) {
        offset += ctx->base_address;
    }

    // Check to see if this symbol is unique and has already been
    // defined
    GSList *p;
    for (p = unique_symbol_resolutions; p && p->data; p = p->next) {
        symbol_resolution *res = (symbol_resolution *) p->data;
#ifdef DEBUG_SYMBOL_RESOLUTION
        printf("Examining %s symbol to check for match with %s\n",
               sym_name, res->symbol_name);
#endif
        if (strcmp(sym_name, res->symbol_name) == 0) {
            memcpy(resolution, res, sizeof(symbol_resolution));
            return;
        }
    }

    GElf_Sym sym;
    if (ctx->gnu_hash != NULL) {
#ifdef DEBUG_SYMBOL_RESOLUTION
        printf("Searching GNU hash for symbol match\n");
#endif
        uint32_t sym_hash = gnu_hash((uint8_t *) sym_name);
        if (bloom_filter_check(sym_hash, ctx->gnu_hash) == TRUE) {
            uint32_t *hashtab = ctx->gnu_hash;
            uint32_t nbuckets = hashtab[0];
            uint32_t sym_offset = hashtab[1];
            uint32_t bloom_size = hashtab[2];
            bloom_t* bloom = (void*)&hashtab[4];
            uint32_t* buckets = (void*)&bloom[bloom_size];
            uint32_t* chain = &buckets[nbuckets];

            uint32_t ndx = buckets[sym_hash % nbuckets];
            if (ndx < sym_offset) {
#ifdef DEBUG_SYMBOL_RESOLUTION
                printf("Index beyond limit\n");
#endif
                return;
            }

            uint32_t current_hash = 0;
            for (; (current_hash & 1) == 0; ++ndx) {
                if (gelf_getsym(ctx->symtab, (int)ndx, &sym) != &sym) {
                    dlog(4,"Failed to get symbol %d for %s: %s", ndx,
                         ctx->path, elf_errmsg(elf_errno()));
                }

                const char *current_name = ctx->strtab + sym.st_name;
                current_hash = chain[ndx - sym_offset];

                if ((sym_hash | 1) == (current_hash | 1)
                        && strcmp(sym_name, current_name) == 0) {
                    if (attempt_resolve_symbol(
                                sym_name,
                                (int)ndx,
                                entry,
                                &sym,
                                ctx,
                                offset,
                                resolution,
                                weak_resolution) == TRUE) {
                        return;
                    }
                }
            }
        } else {
#ifdef DEBUG_SYMBOL_RESOLUTION
            printf("Symbol %s not found in hash table\n", sym_name);
#endif
        }
        return;
    }

    int i;
    for (i = 0; i < (int)(ctx->symtab_sz / ctx->syment_sz); ++i) {
        if (gelf_getsym(ctx->symtab, i, &sym) != &sym) {
            dlog(4,"Failed to get symbol %d for %s: %s", i,
                 ctx->path, elf_errmsg(elf_errno()));
        } else if (strcmp(sym_name, ctx->strtab + sym.st_name) == 0) {
            if (attempt_resolve_symbol(
                        sym_name,
                        i,
                        entry,
                        &sym,
                        ctx,
                        offset,
                        resolution,
                        weak_resolution) == TRUE) {
                return;
            }
        }
    }
}

static void resolve_symbol(
    const char *sym_name,
    got_entry *entry,
    elf_context *ctx,
    GList *elf_contexts,
    symbol_resolution *resolution,
    symbol_resolution *weak_resolution)
{
    // if SYMBOLIC, resolution begins with this ELF object
    if (ctx->symbolic == TRUE) {
        resolve_symbol_in_ctx(sym_name, entry, ctx,
                              resolution, weak_resolution);
    }

    GList *p;
    for (p = elf_contexts;
            resolution->address == 0
            && weak_resolution->address == 0
            && p
            && p->data;
            p = p->next) {
        resolve_symbol_in_ctx(sym_name, entry,
                              p->data, resolution, weak_resolution);
    }
}


static void verify_rela(
    elf_context *ctx,
    Elf_Data *rela_data,
    int rela_limit,
    GList *elf_contexts)
{
    uint64_t offset = 0;
    if (ctx->ehdr.e_type != ET_EXEC) {
        offset += ctx->base_address;
    }

    int i = 0;
    GElf_Rela rela;
    for (i = 0; i < rela_limit; ++i) {
        if (gelf_getrela(rela_data, i, &rela) != &rela) {
            break;
        }
        int sym_ndx = ELF64_R_SYM(rela.r_info);
        uint32_t r_type = ELF64_R_TYPE(rela.r_info);

        GElf_Sym sym;
        if (gelf_getsym(ctx->symtab, sym_ndx, &sym) != &sym) {
            // TODO provide more info about relocation
            report_anomaly_in_ctx(ctx, "Failed to get symbol table "
                                  "entry %d for relocation entry %d: %s ",
                                  sym_ndx, i, elf_errmsg(elf_errno()));
            continue;
        }
        if (sym.st_name > ctx->strtab_sz) {
            // TODO provide more info about relocation
            report_anomaly_in_ctx(ctx, "Symbol for relocation "
                                  "entry %d has st_name %d, exceeding string table "
                                  "size %d",
                                  i, sym.st_name, ctx->strtab_sz);
            continue;
        }
        char *sym_name = ctx->strtab + sym.st_name;

        uint64_t got_entry_address = rela.r_offset;
        if (ctx->ehdr.e_type != ET_EXEC) {
            got_entry_address += ctx->base_address;
        }

        void *relocation_site = ctx->buf + got_entry_address - ctx->base_address;
        uint64_t relocation_value = 0;
        got_entry entry = {0};
        entry.address = got_entry_address;
        entry.relocation_type = r_type;
        entry.symbol_name = ctx->strtab + sym.st_name;
        entry.st_info = sym.st_info;
        elf_context *matching_ctx = NULL;
        symbol_resolution strong_resolution = {0};
        symbol_resolution weak_resolution = {0};
        symbol_resolution *resolution = &strong_resolution;


        switch (r_type) {
        case R_X86_64_GLOB_DAT:
            relocation_value = *(uint64_t*) relocation_site;

            // Find out where the GOT entry points
            entry.contents = relocation_value;
            fill_in_symbol_version_info(sym_ndx, sym.st_shndx, ctx,
                                        &entry.symbol_version,
                                        &entry.hidden,
                                        &entry.expected_library);

            if (entry.contents == 0) {
                break;
            }

            // Find matching symbol
            matching_ctx = ctx_for_address(relocation_value, elf_contexts);
            if (matching_ctx == NULL) {
                report_anomaly_in_ctx(ctx, "R_X86_64_GLOB_DAT GOT entry "
                                      "at %#lx for %s points outside of all file-backed ELF objects "
                                      " to %#lx",
                                      entry.address,
                                      entry.symbol_name,
                                      entry.contents);
                continue;
            }

            entry.matching_library = matching_ctx->path;

            // Search the ELF object"s dynamic symbol table for matches
            add_matching_symbols(&entry, matching_ctx, relocation_value);

            entry.pointer_to_original_contents =
                get_pointer_to_original_got_value(rela.r_offset, ctx);


            // Symbol resolution
            resolve_symbol(sym_name, &entry, ctx,
                           elf_contexts, &strong_resolution, &weak_resolution);
            if (strong_resolution.address == 0) {
                resolution = &weak_resolution;
            }
            if (resolution->address == 0
                    && ELF64_ST_BIND(sym.st_info) == STB_GLOBAL) {
                if (ELF64_ST_TYPE(sym.st_info) == STT_NOTYPE) {
                    continue;
                }
                report_anomaly_in_ctx(ctx, "Failed to resolve symbol "
                                      "'%s'", sym_name);
            }

            break;
        case R_X86_64_JUMP_SLOT:
            relocation_value = *(uint64_t*) relocation_site;

            entry.contents = relocation_value;
            fill_in_symbol_version_info(sym_ndx, sym.st_shndx, ctx,
                                        &entry.symbol_version,
                                        &entry.hidden,
                                        &entry.expected_library);

            if (entry.contents == 0) {
                break;
            }

            // Find matching symbol
            matching_ctx = ctx_for_address(relocation_value, elf_contexts);
            if (matching_ctx == NULL) {
                report_anomaly_in_ctx(ctx, "R_X86_64_JUMP_SLOT GOT entry "
                                      "at %#lx for %s points outside of all file-backed ELF objects "
                                      " to %#lx",
                                      entry.address,
                                      entry.symbol_name,
                                      entry.contents);
                continue;
            }

            entry.matching_library = matching_ctx->path;

            // Search the ELF object"s dynamic symbol table for matches
            add_matching_symbols(&entry, matching_ctx, relocation_value);

            entry.pointer_to_original_contents =
                get_pointer_to_original_got_value(rela.r_offset, ctx);

            // Symbol resolution
            resolve_symbol(sym_name, &entry, ctx,
                           elf_contexts, &strong_resolution, &weak_resolution);
            if (strong_resolution.address == 0) {
                resolution = &weak_resolution;
            }
            if (resolution->address == 0
                    && ELF64_ST_BIND(sym.st_info) == STB_GLOBAL) {
                if (ELF64_ST_TYPE(sym.st_info) == STT_NOTYPE) {
                    continue;
                }
                report_anomaly_in_ctx(ctx, "Failed to resolve symbol "
                                      "'%s'", sym_name);
            }

            break;
        default:
            // TODO other GOT relocations
            continue;
        }

#ifdef GOT_DEBUG
        print_got_entry(&entry);
        print_resolution(resolution);
#endif

        if (resolution->address == 0
                && entry.contents == 0
                && ELF64_ST_BIND(sym.st_info) != STB_GLOBAL) {
#ifdef DEBUG
            printf("Verified %s is unresolved\n", entry.symbol_name);
#endif
            continue;
        }

        if (resolution->address != 0
                && entry.contents == resolution->address) {
#ifdef DEBUG
            printf("Verified %s\n", entry.symbol_name);
#endif
        } else if (entry.pointer_to_original_contents != NULL
                   && ((*(entry.pointer_to_original_contents) == 0
                        && entry.contents == 0)
                       || (*(entry.pointer_to_original_contents) + offset
                           == entry.contents))) {
            if (ctx->relro == TRUE) {
                report_anomaly_in_ctx(ctx, "Unresolved symbol %s in "
                                      "RELRO ELF object", entry.symbol_name);
            }
#ifdef DEBUG
            else {
                printf("Verified %s is unresolved\n", entry.symbol_name);
            }
#endif
        } else if (resolution->address != 0
                   && ELF64_ST_TYPE(resolution->st_info) == STT_GNU_IFUNC) {
#ifndef IGNORE_IFUNCS
            report_anomaly_in_ctx(ctx, "Unable to verify IFUNC %s",
                                  entry.symbol_name);
            print_got_entry(&entry);
            print_resolution(resolution);
#endif
        } else {
            printf("Anomalous GOT entry in %s\n", ctx->path);
            print_got_entry(&entry);
            print_resolution(resolution);
            passed = FALSE;
        }

        //Clean up entry memory
        g_slist_free_full(entry.matching_symbols, (GDestroyNotify)free);
    }
}


static void verify_GOT(elf_context *ctx, GList *elf_contexts)
{
#ifdef DEBUG
    printf("Verifying GOT of %s\n", ctx->path);
#endif
    // TODO 32-bit and REL support
    if (ctx->rela_sz > 0 && ctx->rela != NULL) {
        int rela_limit = (int)(ctx->rela_sz / sizeof(Elf64_Rela));
        verify_rela(ctx, ctx->rela, rela_limit, elf_contexts);
    }

    if (ctx->jmprel_sz > 0 && ctx->jmprel != NULL) {
        int rela_limit = (int)(ctx->jmprel_sz / sizeof(Elf64_Rela));
        verify_rela(ctx, ctx->jmprel, rela_limit, elf_contexts);
    }
}


static void verify_global_offset_tables(GList *elf_contexts)
{
    GList *p;
    for (p = elf_contexts; p && p->data; p = p->next) {
        verify_GOT(p->data, elf_contexts);
    }
}

/* Looks up the executable path from /proc/<PID>/exe and makes sure that
* matches the path from the memory mapping for an ELF object. */
static void verify_exe_path(
    const char *pid_string,
    const char *elf_path)
{
    if(strnlen(pid_string, (size_t)(g_num_digits_pid + 1)) > (size_t) g_num_digits_pid) {
        report_anomaly("Given invalid PID %s", pid_string);
        return;
    }

    char *exe_path = get_executable_path(pid_string);
    if (!exe_path) {
        report_anomaly("Unable to get executable path for PID: %s", pid_string);
        return;
    }

    if (strcmp(exe_path, elf_path) != 0) {
        report_anomaly("The executable file mapping beginning at the "
                       "executable base load address has a different path than "
                       "/proc/%s/exe: '%s' rather than '%s'",
                       pid_string, elf_path, exe_path);
    }

    free(exe_path);
    exe_path = NULL;
}

static elf_context *create_vdso_ctx(const char *pid_string)
{
    elf_context *ctx;

    if(strnlen(pid_string, (size_t)(g_num_digits_pid + 1)) > (size_t) g_num_digits_pid) {
        report_anomaly("Given invalid PID");
        return NULL;
    }

    memory_mapping *vdso_mapping = get_mapping(pid_string, "[vdso]");
    if (vdso_mapping == NULL) {
        report_anomaly("Failed to find [vdso] mapping");
        return NULL;
    }
    mapping_group *grp = create_mapping_group(vdso_mapping);
    if(grp == NULL) {
        report_anomaly("Failed to create vdso mapping group");
        return NULL;
    }

    file_mapping_buffer *mb = create_file_mapping_buffer(grp);
    if(mb == NULL) {
        report_anomaly("Failed to create file mapping buffer for vdso mapping group");
        return NULL;
    }

    /* This call takes ownership of some data in the file_mapping_buffer, cannot free */
    ctx = scan_vdso(mb);
    if(ctx == NULL) {
        free_file_mapping_buffer((gpointer)mb, (gpointer)grp->path);
        free_mapping_group(grp);
        free_file_mapping((gpointer)vdso_mapping, (gpointer)pid_string);
    }

    return ctx;
}

static GList *insert_vdso_ctx(
    GList *elf_contexts,
    elf_context *vdso_ctx)
{
    // Assume the contexts are already ordered with the executable
    // context first

    // link_map order puts the VDSO second, but in practice, it looks
    // like rtld doesn't resolve things to vdso, at least not second
    // (after the executable), so put it at the end so it doesn't get in
    // the way of symbol resolution.
    //return g_list_insert(elf_contexts, vdso_ctx, 1);

    return g_list_append(elf_contexts, vdso_ctx);
}

static char *get_cmdline(const char *pid)
{
    char path[PATH_MAX] = "/proc/";

    strncat(path, pid, (size_t)g_num_digits_pid);
    strncat(path, "/cmdline", 9);

    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        dlog(4, "Failed to open %s", path);
        return NULL;
    }
    char *buf = NULL;
    size_t buf_sz = 0;

    ssize_t bytes_read = 0;
    bytes_read = getdelim(&buf, &buf_sz, -1, fp);
    int i = 0;
    for (i = 0; i + 1 < bytes_read; ++i) {
        if (buf[i] == '\0') {
            buf[i] = ' ';
        }
    }

    fclose(fp);
    return buf;
}

static void scan_process(pid_t pid)
{
    int res = 0;
    char *pid_string;

    pid_string = malloc(g_num_digits_pid + 1);
    if(pid_string == NULL) {
        dlog(0, "Unable to allocate memory for a string representation of a PID\n");
        return;
    }

    res = snprintf(pid_string, g_num_digits_pid + 1, "%ld",
                   (long int)pid);
    if (res < 0) {
        dlog(1, "Unable to convert the PID into string form\n");
        free(pid_string);
        return;
    }

    char *cmdline = get_cmdline(pid_string);
    if (!cmdline) {
        report_anomaly("Unable to access command line information of process");
        return;
    }

    dlog(4, "Scanning PID %s: %s\n", pid_string, cmdline);
    free(cmdline);

    // Set the ELF version at which we want to operate
    if (elf_version(EV_CURRENT) == EV_NONE) {
        report_anomaly(" ELF library initialization "
                       " failed : %s ", elf_errmsg(elf_errno()));
        return;
    }

    if(open_mem_fd(pid_string) < 0) {
        report_anomaly("Unable to open memory of process for reading\n");
        return;
    }

    GSList *elf_mapping_groups = get_elf_mapping_groups(pid_string);

#ifdef DEBUG
    print_mapping_groups(elf_mapping_groups);
#endif
    GSList *elf_buffers = get_elf_buffers(elf_mapping_groups);

    GSList *p;
    GList *elf_contexts = NULL;
    for (p = elf_buffers; p && p->data; p = p->next) {
        file_mapping_buffer *mb = (file_mapping_buffer *)p->data;

        elf_contexts = g_list_prepend(elf_contexts, scan_elf_object(mb));
    }
    elf_contexts = g_list_reverse(elf_contexts);

    uint64_t exe_base_load_addr =
        get_executable_base_load_address(pid_string);
    if (!exe_base_load_addr || move_exe_context_to_front(&elf_contexts, exe_base_load_addr) < 0) {
        report_anomaly("Could not find the ELF context for the executable");
        return;
    }

    verify_exe_path(pid_string, ((elf_context *)elf_contexts->data)->path);

    uint64_t link_map_address = find_link_map_address(elf_contexts);
#ifdef EXPERIMENTAL
    // XXX: This works on a CentOS 7 VM - look into applicability to others
    if (link_map_address == 0) {
        link_map_address = guess_link_map_address(elf_contexts);
    }
#endif

    if (link_map_address != 0) {
        GSList *linkmap_list = retrieve_link_map(link_map_address);

        if (linkmap_list == NULL) {
            report_anomaly("Unable to retrieve link map based on address\n");
            return;
        }

        if (verify_executable_link_map_entry(linkmap_list, elf_contexts) == 0
                && verify_vdso_link_map_entry(linkmap_list, pid_string) == 0
                && reorder_contexts(elf_contexts, linkmap_list) == 0) {
            elf_context *vdso_ctx = create_vdso_ctx(pid_string);
            elf_contexts = insert_vdso_ctx(elf_contexts, vdso_ctx);

#ifdef DEBUG_LINK_MAP_ORDER
            puts("link_map order:");
            GList *tmp;
            for (tmp = elf_contexts; tmp && tmp->data; tmp = tmp->next) {
                printf("  %s\n", ((elf_context *) tmp->data)->path);
            }
#endif

            // We now have the ELF contexts arranged in link_map order,
            // so we are ready to do symbol resolution and check the GOT
            // entries.
            verify_global_offset_tables(elf_contexts);
        }

        //All of the members of this list are link_map_wrappers
        if(linkmap_list) {
            for(p = linkmap_list; p && p->data; p = p->next) {
                link_map_wrapper *wrapper = (link_map_wrapper *)p->data;
                free(wrapper->link_map.l_name);
                free(wrapper);
            }

            g_slist_free(linkmap_list);
        }
    } else {
        fputs("Failed to find the link_map from any of the ELF "
              "objects - cannot verify linking structures\n", stderr);
    }

    free(pid_string);
    g_list_free_full(elf_contexts, (GDestroyNotify)free_elf_context);
    g_slist_free_full(elf_mapping_groups, (GDestroyNotify)free_mapping_group);
    // Free the file_mapping_buffers but don't free the buffers storing
    // the raw ELF objects
    g_slist_foreach(elf_buffers, free_file_mapping_buffer,
                    GINT_TO_POINTER(TRUE));
    g_slist_free(elf_buffers);
}

static int is_pid(uint32_t pid)
{
    int res = 0;
    FILE *fp = NULL;
    char buf[PATH_MAX] = "/proc/", *pid_string = NULL;

    if (pid > g_max_system_pid) {
        dlog(1, "The PID %" PRIu32 " is larger than the largest possible PID %" PRIu32 " on the system\n",
             pid, g_max_system_pid);
        return FALSE;
    }

    pid_string = malloc(g_num_digits_pid + 1);
    if(pid_string == NULL) {
        dlog(0, "Unable to allocate memory for a string representation of a PID\n");
        return FALSE;
    }

    res = snprintf(pid_string, g_num_digits_pid + 1, "%" PRIu32 "", pid);
    if (res < 0) {
        dlog(1, "Unable to convert the PID into string form\n");
        free(pid_string);
        return FALSE;
    }

    strncat(buf, pid_string, (size_t)g_num_digits_pid);
    strncat(buf, "/stat", 6);
    free(pid_string);

    errno = 0;
    fp = fopen(buf, "rb");
    if (fp == NULL) {
        dlog(1, "Cannot open the process stat file %s: error - %s\n", buf, strerror(errno));
        return FALSE;
    }

    fclose(fp);
    return TRUE;
}

/* This function will be listed in a header file and will expose the got_measurer
 * functionality to other binaries */
int measure_got(const uint32_t pid_u)
{
    int wstatus, res = 0;
    pid_t pid;
    uid_t uid;

    //One could reacquire the system's maximum PID everytime a PID is read, but
    //this might be expensive and unecessary
    if ((g_max_system_pid = get_pid_max_linux_64bit(&g_num_digits_pid)) == 0) {
        dlog(0, "Failed to get PID limit\n");
        return -1;
    }

    //Determine if the argument is valid
    if (is_pid(pid_u) == FALSE) {
        dlog(1, "Given invalid PID\n");
        return -1;
    }

    /*
     * The reason for accepting a uint32_t, checking it, and then converting to the pid_t
     * type is two fold:
     * 1. The measurement graph pid_address struct stores the PID as a uint32_t as opposed
     * to as a pid_t
     * 2. If given a choice between forcing the client to handle this process of checking
     * the PID, or instead doing it in this code, I believe this code should handle it
     * Converting to a pid_t is useful because several functions used further ahead take a
     * pid_t
     */
    pid = pid_u;

    errno = 0;
    uid = getuid();
    if(errno) {
        dlog(0, "Unable to get process UID\n");
        return -1;
    }

    /* This ASP is SUID'd, and so should be run by APBs as root (UID 0) HOWEVER,
     * when run as a test, the UID should be nonzero, because the test is run
     * as nonprivileged. In that case, ptrace commands are almost certainly not
     * permitted, hence this guard */
    if(uid == 0) {
        errno = 0;
        ptrace(PTRACE_ATTACH, pid, NULL, NULL);
        if(errno) {
            dlog(0, "Unable to trace process %ld: %s\n",
                 (long int)pid, strerror(errno));
            return -1;
        }

        res = waitpid(pid, &wstatus, 0);

        if(res < 0 || !WIFSTOPPED(wstatus)) {
            dlog(1, "Unable to properly wait on traced process of pid %ld,"
                 "skipping measurement\n", (long int)pid);
            res = -1;
        }
    }

    dlog(3, "Scanning PID %ld\n", (long int)pid);

    if(res >= 0) {
        scan_process(pid);
    }

    if(uid == 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
    }

    if (passed == TRUE) {
        dlog(4, "Measurement passed!\n");
        return 0;
    } else {
        dlog(4, "Measurement failed!\n");
        return -1;
    }
}
