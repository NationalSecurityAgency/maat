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
#ifndef __ELFHEADER_TYPE_H__
#define __ELFHEADER_TYPE_H__

/*! \file
 * Gathers information from the Elf Header and Symbols of a File.
 */

#include <glib.h>
#include <gelf.h>
#include <measurement_spec/meas_spec-api.h>


/**
 *  OVAL process metadata measurement_type universally unique 'magic' id number
 */
#define LIBELF_TYPE_MAGIC	(3202) 		//!< UUID Magic Number = 3202

/**
 *  OVAL process metadata measurement_type universally unique name
 */
#define LIBELF_TYPE_NAME	"elfheader"


#define MAX_PATH_LENGTH         64		//!< Max Path Length = 64 
#define MAX_SECTION_NAME_LENGTH 64		//!< Max Section Name LEngth = 64

/**
custom built elf measurement_data
 */
typedef struct elfheader_measurement_data {
    struct           measurement_data d;    	//!< Default Measurmeent Structure
    char *           filename;			//!< Elf File Being Parsed
    GElf_Ehdr        elf_header;		//!< GELF HEader resides at the begining of file and holds a "road map" describing the files organization.
    size_t	     nr_phdrs;
    GElf_Phdr        *program_headers;		//!< GELF Program Header describing segment system needs to pepare for execution
    GList            *section_headers;		//!< List of Section headers
    GList            *symbols;			//!< List of Symbols
    GList            *dependencies;		//!< List of Dependencies
} elfheader_meas_data;

/**
 * Section includes name and header
 */
typedef struct elf_section_header {
    char *        section_name;			//!< Section Name
    GElf_Shdr     section_hdr;			//!< GELF Section Header (Name, Type, Flags, Addr, Offset, ...)
} elf_sct_hdr;

/**
 * Section includes name and symbol header
 */
typedef struct elf_symbol_header {
    char *     symbol_name;			//!< Symbol Name
    char *     file_name;			//!< File Name that the symbol resides in
    char *     ref_name;			//!< Linker Package Name for File
    int        version;				//!< Version of the File Name Symbol Resides In
    GElf_Sym   symbol;				//!< GELF Symbol (Name, Info, Other, SHNDX, Value, Size)
} elf_symbol;

/*! Allocate Memory for new ElfHeader Measurement
 \returns measurement_data struct
 */
//measurement_data *elfheader_type_alloc_data(void);


/*! Free Memory Allocated for Measurement
 \param measurement_data - measurement object
 */
//void elfheader_type_free_data(measurement_data *d);

/**
 * name for file data measurement_type
 */
extern measurement_type elfheader_measurement_type;

#endif /* __ELFHEADER_TYPE_H__ */

