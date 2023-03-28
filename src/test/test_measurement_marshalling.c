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

#include <check.h>
#include <maat-basetypes.h>
#include <util/util.h>

measurement_data *do_serialize_unserialize(measurement_data *d)
{
    int ret_val = 0;
    char *serial_data = NULL;
    size_t serial_data_size = 0;
    ret_val = d->type->serialize_data(d, &serial_data, &serial_data_size);
    fail_if(ret_val != 0, "Marshalling data of type %s failed", d->type->name);
    fail_if(serial_data == NULL, "Marshalling data of type %s failed", d->type->name);
    measurement_data *nmd = NULL;
    ret_val = d->type->unserialize_data(serial_data, serial_data_size, &nmd);
    fail_if(ret_val != 0, "Unmarshalling data of type %s failed (ret_val %d)", d->type->name, ret_val);
    fail_if(nmd == NULL, "Unmarshalling data of type %s failed (null)", d->type->name);

    free(serial_data);
    return nmd;
}

int do_get_feature(measurement_data *d, char * feature, GList **out)
{
    int ret_val;
    ret_val = d->type->get_feature(d, feature, out);
    fail_if(ret_val != 0, "Get Feature of data type %s failed", d->type->name);
    return ret_val;
}

START_TEST(test_enumeration_data)
{
    int rc;
    int added_count = 0;
    dlog(6, "Testing enumeration measurement type\n");

    measurement_data *md = alloc_measurement_data(&enumeration_measurement_type);
    fail_if(md == NULL, "Failed to allocate measurement data of enumeration measurement type\n");

    enumeration_data *d = container_of(md, enumeration_data, meas_data);

    // Add a single entry
    char *entry = strdup("foobar");
    fail_if(entry == NULL, "Failed to allocate memory for new entry\n");
    rc = enumeration_data_add_entry(d, entry);
    fail_if(rc != 0, "Failed to add entry to enumeration measurement data, returned %d\n", rc);
    added_count += 1;

    // Add a GList of entries
    GList *tmp_entries = NULL;
    int i = 0;
    for(i; i < 2; i++) {
        entry = strdup("barfoo");
        fail_if(entry == NULL, "Failed to allocate memory for new entry in glist\n");
        tmp_entries = g_list_append(tmp_entries, entry);
        added_count += 1;
    }

    rc = enumeration_data_add_entries(d, tmp_entries);
    fail_if(rc != 0, "Failed to add GList of entries to enumeration measurement data, returned %d\n", rc);

    enumeration_data *d2 = (enumeration_data*)do_serialize_unserialize(md);

    fail_if(d->num_entries != d2->num_entries, "Number of entries does not match\n");

    // Get feature
    GList *d_entries = NULL;
    rc = do_get_feature(&d->meas_data, "entries", &d_entries);
    fail_if(rc != 0, "Measurement data get feature returned %d\n", rc);
    fail_if(d_entries == NULL, "Measurement data get feature returned NULL glist of entries\n");

    GList *d2_entries = NULL;
    rc = do_get_feature(&d2->meas_data, "entries", &d2_entries);
    fail_if(rc != 0, "Measurement data get feature returned %d\n", rc);
    fail_if(d_entries == NULL, "Measurement data get feature returned NULL glist of entries\n");

    GList *iter1, *iter2;
    for(iter1 = d_entries, iter2 = d2_entries;
            iter1 && iter2;
            iter1 = g_list_next(iter1), iter2 = g_list_next(iter2)) {
        char *tmp1, *tmp2;
        tmp1 = (char *) iter1->data;
        tmp2 = (char *) iter2->data;
        fail_if(strcmp(tmp1, tmp2) != 0, "Expected %s got %s\n", tmp1, tmp2);
    }

    // Double check length with inputs
    int len = g_list_length(d_entries);
    fail_if(len != d2->num_entries, "Expected %d entries, got %d\n", d2->num_entries, len);
    fail_if(len != added_count, "Added %d entries, got %d\n", added_count, len);

    g_list_free_full(d_entries, (GDestroyNotify)free);
    g_list_free_full(d2_entries, (GDestroyNotify)free);
    free_measurement_data(&d->meas_data);
    free_measurement_data(&d2->meas_data);
}
END_TEST

START_TEST(test_filedata)
{
    dlog(6, "Testing filedata measurement type\n");
    filedata_measurement_data *d = (filedata_measurement_data*)alloc_measurement_data(&filedata_measurement_type);
    size_t size = random() % 65536;
    int i;

    fail_if(d == NULL, "Failed to create filedata measurement data");
    d->contents		= malloc(size);
    fail_if(d->contents == NULL, "Failed to allocate %u bytes for file data contents", size);

    d->contents_length	= size;
    for(i=0; i<size; i++) {
        d->contents[i] = (uint8_t)(random() % 256);
    }
    filedata_measurement_data *d2 = (filedata_measurement_data*)do_serialize_unserialize(&d->meas_data);
    fail_if(d2->contents_length != d->contents_length,
            "Unmarshalled filedata data has content length %u. Expected %u",
            d2->contents_length, d->contents_length);

    fail_if(memcmp(d2->contents, d->contents, d2->contents_length),
            "Unmarshalled filedata data differs from original data.");

    free_measurement_data(&d->meas_data);
    free_measurement_data(&d2->meas_data);
}
END_TEST

START_TEST(test_filename_data)
{
    filename_measurement_data *d = (filename_measurement_data*)alloc_measurement_data(&filename_measurement_type);
    size_t size = random() % 1024;
    int i;
    dlog(6, "Testing filename measurement type\n");
    fail_if(d == NULL, "Failed to create filedata measurement data");
    d->contents		= malloc(size);
    fail_if(d->contents == NULL, "Failed to allocate %u bytes for file data contents", size);

    for(i=0; i<size-1; i++) {
        d->contents[i] = 'a'+(uint8_t)(random() % 26);
    }
    d->contents[size-1] = '\0';

    filename_measurement_data *d2 = (filename_measurement_data*)do_serialize_unserialize(&d->meas_data);
    fail_if(strcmp(d2->contents, d->contents),
            "Unmarshalled filename data differs from original data. orig: %s unmarshalled: %s", d->contents, d2->contents);

    free_measurement_data(&d->meas_data);
    free_measurement_data(&d2->meas_data);
}
END_TEST

START_TEST(test_sha1_data)
{
    sha1hash_measurement_data *d = (sha1hash_measurement_data*)alloc_measurement_data(&sha1hash_measurement_type);
    int i;
    dlog(6, "Testing sha1 measurement type\n");
    fail_if(d == NULL, "Failed to create filedata measurement data");

    for(i=0; i<SHA1HASH_LEN; i++) {
        d->sha1_hash[i] = (uint8_t)(random() % 255);
    }

    sha1hash_measurement_data *d2 = (sha1hash_measurement_data*)do_serialize_unserialize(&d->meas_data);
    fail_if(memcmp(d2->sha1_hash, d->sha1_hash, SHA1HASH_LEN),
            "Unmarshalled sha1 data differs from original data.");

    free_measurement_data(&d->meas_data);
    free_measurement_data(&d2->meas_data);
}
END_TEST

START_TEST(test_sha256_data)
{
    sha256_measurement_data *d = (sha256_measurement_data*)alloc_measurement_data(&sha256_measurement_type);
    int i;
    dlog(6, "Testing sha256 measurement type\n");
    fail_if(d == NULL, "Failed to create sha256 measurement data");

    for(i=0; i<SHA256_TYPE_LEN; i++) {
        d->sha256_hash[i] = (uint8_t)(random() % 255);
    }

    sha256_measurement_data *d2 = (sha256_measurement_data*)do_serialize_unserialize(&d->meas_data);
    fail_if(memcmp(d2->sha256_hash, d->sha256_hash, SHA256_TYPE_LEN),
            "Unmarshalled sha256 data differs from original data.");

    free_measurement_data(&d->meas_data);
    free_measurement_data(&d2->meas_data);
}
END_TEST

START_TEST(file_metadata)
{
    struct file_metadata_measurement_data *fmd =
        (typeof(fmd))alloc_measurement_data(&file_metadata_measurement_type);
    int i;
    char *ptr;
    fail_if(fmd == NULL, "Failed to allocated file metadata measurement data");
    ptr = (char*)&fmd->file_metadata;
    for(i=0; i<sizeof(fmd->file_metadata); i++) {
        ptr[i] = (char)(random() % 256);
    }
    struct file_metadata_measurement_data *fmd2 =
        (typeof(fmd2))do_serialize_unserialize(&fmd->meas_data);
    fail_if(memcmp(&fmd2->file_metadata, &fmd->file_metadata, sizeof(fmd->file_metadata)),
            "Unmarshalled file meta data differs from original");

    free_measurement_data(&fmd->meas_data);
    free_measurement_data(&fmd2->meas_data);
}
END_TEST

START_TEST(test_mtab_data)
{
    mtab_data *d = (mtab_data*)alloc_measurement_data(&mtab_measurement_type);
    struct mntent ent[2] = {
        {
            .mnt_fsname = "mnt_fsname0",
            .mnt_dir    = "mnt_dir0",
            .mnt_type   = "mnt_type0",
            .mnt_opts   = "mnt_opts0",
            .mnt_freq   = 0,
            .mnt_passno = 1
        },
        {
            .mnt_fsname = "mnt_fsname1",
            .mnt_dir    = "mnt_dir1",
            .mnt_type   = "mnt_type1",
            .mnt_opts   = "mnt_opts1",
            .mnt_freq   = 0,
            .mnt_passno = 1
        }
    };

    fail_if(d==NULL, "Failed to allocate mtab data");
    fail_if(mtab_data_add_mntent(d, &ent[0]) != 0, "Failed to add first mntent to data");
    fail_if(mtab_data_add_mntent(d, &ent[1]) != 0, "Failed to add second mntent to data");

    mtab_data *d2 = (mtab_data*)do_serialize_unserialize(&d->d);

    GList *iter1, *iter2;
    for(iter1 = g_list_first(d->mntents), iter2 = g_list_first(d2->mntents);
            iter1 != NULL && iter2 != NULL;
            iter1 = g_list_next(iter1), iter2 = g_list_next(iter2)) {

        struct mntent *ent1 = (struct mntent*)iter1->data;
        struct mntent *ent2 = (struct mntent*)iter2->data;
        fail_if(strcmp(ent1->mnt_fsname, ent2->mnt_fsname) != 0, "mnt_fsname fields don't match");
        fail_if(strcmp(ent1->mnt_dir, ent2->mnt_dir) != 0,	 "mnt_dir fields don't match");
        fail_if(strcmp(ent1->mnt_type, ent2->mnt_type) != 0,	 "mnt_type fields don't match");
        fail_if(strcmp(ent1->mnt_opts, ent2->mnt_opts) != 0,	 "mnt_opts fields don't match");
        fail_if(ent1->mnt_freq != ent2->mnt_freq,		 "mnt_freq fields don't match");
        fail_if(ent1->mnt_passno != ent2->mnt_passno,		 "mnt_passno fields don't match");
    }

    fail_if(iter1 != NULL, "Unserialized data has extra entries");
    fail_if(iter2 != NULL, "Unserialized data missing entries");

    free_measurement_data(&d->d);
    free_measurement_data(&d2->d);
}
END_TEST

START_TEST(test_report_data)
{
    report_data *r1 = report_data_with_text(strdup("hello world"),
                                            strlen("hello world")+1);
    fail_if(r1 == NULL, "Failed to allcate report data");

    report_data *r2 = (report_data*)do_serialize_unserialize(&r1->d);

    fail_if(r1->text_data_len != r2->text_data_len,
            "Unserialized data length not equal to original data length");
    fail_if(memcmp(r1->text_data, r2->text_data, r1->text_data_len) != 0,
            "Unserialized data doesn't match serialized data");

    free_measurement_data(&r1->d);
    free_measurement_data(&r2->d);
}
END_TEST

START_TEST(test_path_list_data)
{
    measurement_data *d1 = alloc_measurement_data(&path_list_measurement_type);
    struct stat stats;
    fail_if(d1 == NULL, "failed to allocate path_list data");

    fail_if(stat("/dev/null", &stats) != 0, "Failed to stat /dev/null");

    measurement_data *d2 = do_serialize_unserialize(d1);

    /* FIXME: check to ensure the two are equal */

    free_measurement_data(d1);
    free_measurement_data(d2);
}
END_TEST

START_TEST(test_proc_root_data)
{
    proc_root_meas_data *d1 = (proc_root_meas_data*)alloc_measurement_data(&proc_root_measurement_type);

    d1->rootlinkpath = strdup("/usr/local/bin");

    proc_root_meas_data *d2 = (proc_root_meas_data*)do_serialize_unserialize(&d1->meas_data);

    fail_if(strcmp(d1->rootlinkpath, d2->rootlinkpath) != 0, "Root Path Links Do Not Match");

    free_measurement_data(&d1->meas_data);
    free_measurement_data(&d2->meas_data);
}
END_TEST

START_TEST(test_elf_header_data)
{
    elfheader_meas_data *d1 = (elfheader_meas_data *)alloc_measurement_data(&elfheader_measurement_type);
    fail_if(d1 == NULL, "failed to allocate elf header data");

    //initialize ehdr and phdr
    d1->filename = strdup("helloworld");
    memcpy(d1->elf_header.e_ident, "IDENT", strlen("IDENT")+1);
    d1->elf_header.e_machine = 0;
    d1->elf_header.e_version = 1;
    d1->elf_header.e_entry = 2;
    d1->elf_header.e_phoff = 3;
    d1->elf_header.e_shoff = 4;
    d1->elf_header.e_flags = 5;
    d1->elf_header.e_ehsize = 6;
    d1->elf_header.e_phentsize = 7;
    d1->elf_header.e_shentsize = 8;
    d1->elf_header.e_shnum = 9;
    d1->elf_header.e_shstrndx = 10;

    d1->nr_phdrs			= 1;
    d1->program_headers			= calloc(1, sizeof(GElf_Phdr));
    d1->program_headers[0].p_type	= 11;
    d1->program_headers[0].p_flags	= 0xdeadbeef;
    d1->program_headers[0].p_vaddr	= 0xfeedfaceecafdeef;
    d1->program_headers[0].p_paddr	= 0xcafecafecafecafe;
    d1->program_headers[0].p_filesz	= 0x1000;
    d1->program_headers[0].p_memsz	= 0x4000;
    d1->program_headers[0].p_align	= 0x1000;

    // initialize section headers
    elf_sct_hdr *elfSecHdr = calloc(1, sizeof(elf_sct_hdr));
    elfSecHdr->section_name = strdup("Section1");
    elfSecHdr->section_hdr.sh_name = 20;
    elfSecHdr->section_hdr.sh_type = 21;
    elfSecHdr->section_hdr.sh_flags = 22;
    elfSecHdr->section_hdr.sh_offset = 23;
    elfSecHdr->section_hdr.sh_size = 24;
    elfSecHdr->section_hdr.sh_link = 25;
    elfSecHdr->section_hdr.sh_info = 26;
    elfSecHdr->section_hdr.sh_addralign = 27;
    elfSecHdr->section_hdr.sh_entsize = 28;
    d1->section_headers = g_list_append(d1->section_headers, elfSecHdr);

    elfSecHdr = calloc(1, sizeof(elf_sct_hdr));
    elfSecHdr->section_name = strdup("Section2");
    elfSecHdr->section_hdr.sh_name = 30;
    elfSecHdr->section_hdr.sh_type = 31;
    elfSecHdr->section_hdr.sh_flags = 32;
    elfSecHdr->section_hdr.sh_offset = 33;
    elfSecHdr->section_hdr.sh_size = 34;
    elfSecHdr->section_hdr.sh_link = 35;
    elfSecHdr->section_hdr.sh_info = 36;
    elfSecHdr->section_hdr.sh_addralign = 37;
    elfSecHdr->section_hdr.sh_entsize = 38;
    d1->section_headers = g_list_append(d1->section_headers, elfSecHdr);


    elf_symbol *symbol = calloc(1, sizeof(elf_symbol));
    symbol->symbol_name = strdup("SYMBOL1");
    symbol->file_name = strdup("FILE1");
    symbol->ref_name = strdup("REF1");
    symbol->version = 4;
    symbol->symbol.st_name = 0;
    symbol->symbol.st_info = 'a';
    symbol->symbol.st_other = 'b';
    symbol->symbol.st_shndx = 1;
    symbol->symbol.st_value = 2;
    symbol->symbol.st_size = 3;
    d1->symbols = g_list_append(d1->symbols, symbol);

    elf_symbol *symbol2 = calloc(1, sizeof(elf_symbol));
    symbol2->symbol_name = strdup("SYMBOL2");
    symbol2->file_name = strdup("libc.so");
    symbol2->ref_name = strdup("GLIB2.4");
    symbol2->version = 8;
    symbol2->symbol.st_name = 9;
    symbol2->symbol.st_info = 'q';
    symbol2->symbol.st_other = 'w';
    symbol2->symbol.st_shndx = 10;
    symbol2->symbol.st_value = 11;
    symbol2->symbol.st_size = 12;
    d1->symbols = g_list_append(d1->symbols, symbol2);

    char * dep_file_name = strdup("testfile111.so");
    d1->dependencies = g_list_append(d1->dependencies, dep_file_name);

    char * dep_file_name2 = malloc(strlen("testfile2.so") + 1);
    memcpy(dep_file_name2, "testfile2.so", strlen("testfile2.so")+1);
    d1->dependencies = g_list_append(d1->dependencies, dep_file_name2);

    elfheader_meas_data *d2 = container_of(do_serialize_unserialize(&d1->d), elfheader_meas_data, d);

    fail_if(strcmp(d2->filename, d1->filename) != 0, "Filename fields don't match");
    fail_if(strcmp(d2->elf_header.e_ident, d1->elf_header.e_ident) != 0, "EHdr Ident fields don't match");
    fail_if(d2->elf_header.e_machine != d1->elf_header.e_machine, "EHdr Machine fields don't match");
    fail_if(d2->elf_header.e_version != d1->elf_header.e_version, "EHdr Version fields don't match");
    fail_if(d2->elf_header.e_entry != d1->elf_header.e_entry, "EHdr Entry fields don't match");
    fail_if(d2->elf_header.e_phoff != d1->elf_header.e_phoff, "EHdr Phoff fields don't match");
    fail_if(d2->elf_header.e_shoff != d1->elf_header.e_shoff, "EHdr Shoff fields don't match");
    fail_if(d2->elf_header.e_flags != d1->elf_header.e_flags, "EHdr Flags fields don't match");
    fail_if(d2->elf_header.e_ehsize != d1->elf_header.e_ehsize, "EHdr Ehsize fields don't match");
    fail_if(d2->elf_header.e_phentsize != d1->elf_header.e_phentsize, "EHdr Phentsize fields don't match");
    fail_if(d2->elf_header.e_shentsize != d1->elf_header.e_shentsize, "EHdr Shentsize fields don't match");
    fail_if(d2->elf_header.e_shnum != d1->elf_header.e_shnum, "EHdr Shnum fields don't match");
    fail_if(d2->elf_header.e_shstrndx != d1->elf_header.e_shstrndx, "EHdr Shstrndx fields don't match");

    fail_if(d2->nr_phdrs != d1->nr_phdrs, "Number of phdrs differs.");
    fail_if(memcmp(d2->program_headers, d1->program_headers,
                   d1->nr_phdrs * sizeof(GElf_Phdr)) != 0,
            "PHdrs differ");

    GList *iter1, *iter2;
    for(iter1 = g_list_first(d1->section_headers), iter2 = g_list_first(d2->section_headers);
            iter1 != NULL && iter2 != NULL;
            iter1 = g_list_next(iter1), iter2 = g_list_next(iter2)) {

        elf_sct_hdr *hd1 = (elf_sct_hdr *)iter1->data;
        elf_sct_hdr *hd2 = (elf_sct_hdr *)iter2->data;

        fail_if(hd1->section_hdr.sh_name != hd2->section_hdr.sh_name, "sh_name don't match");
        fail_if(hd1->section_hdr.sh_flags != hd2->section_hdr.sh_flags, "sh_flags don't match");
        fail_if(hd1->section_hdr.sh_entsize != hd2->section_hdr.sh_entsize, "sh_entsize don't match");
        fail_if(strcmp(hd1->section_name, hd2->section_name) != 0, "section names don't match");
    }

    for(iter1 = g_list_first(d1->symbols), iter2 = g_list_first(d2->symbols);
            iter1 != NULL && iter2 != NULL;
            iter1 = g_list_next(iter1), iter2 = g_list_next(iter2)) {

        elf_symbol * sym1 = (elf_symbol *)iter1->data;
        elf_symbol * sym2 = (elf_symbol *)iter2->data;

        fail_if(strncmp(sym1->symbol_name, sym2->symbol_name, strlen(sym1->symbol_name)) != 0, "Symbol names don't match");
        fail_if(strncmp(sym1->file_name, sym2->file_name, strlen(sym1->file_name)) != 0, "File names don't match");
        fail_if(strncmp(sym1->ref_name, sym2->ref_name, strlen(sym1->ref_name)) != 0, "Reference names don't match");

        fail_if(sym1->version != sym2->version, "Symbol Versions don't match");
        fail_if(sym1->symbol.st_name != sym2->symbol.st_name, "Symbol Name does not match");
        fail_if(sym1->symbol.st_info != sym2->symbol.st_info, "Symbol info does not match");
        fail_if(sym1->symbol.st_other != sym2->symbol.st_other, "Symbol other does not match");
        fail_if(sym1->symbol.st_shndx != sym2->symbol.st_shndx, "Symbol section does not match");
        fail_if(sym1->symbol.st_value != sym2->symbol.st_value, "Symbol value does not match");
        fail_if(sym1->symbol.st_size != sym2->symbol.st_size, "Symbol size does not match");

    }

    for(iter1 = g_list_first(d1->dependencies), iter2 = g_list_first(d2->dependencies);
            iter1 != NULL && iter2 != NULL;
            iter1 = g_list_next(iter1), iter2 = g_list_next(iter2)) {


        char * dep1 = (char *) iter1->data;
        char * dep2 = (char *) iter2->data;

        dlog(0, "%s == %s\n", dep1, dep2);
        fail_if(strncmp(dep1, dep2, strlen(dep1)) != 0, "Dependency names don't match");
    }

    // Test Get Feature
    GList * dependList = NULL;
    int featureSuccess = do_get_feature(&d1->d, "files", &dependList);
    fail_if(featureSuccess != 0, "Get Feature Failed\n");

    for(iter1 = g_list_first(d1->dependencies), iter2 = g_list_first(dependList);
            iter1 != NULL && iter2 != NULL;
            iter1 = g_list_next(iter1), iter2 = g_list_next(iter2)) {


        char * dep1 = (char *) iter1->data;
        char * dep2 = (char *) iter2->data;

        dlog(0, "%s == %s\n", dep1, dep2);
        fail_if(strcmp(dep1, dep2) != 0, "Dependency names don't match");
    }

    g_list_free_full(dependList, free);

    free_measurement_data(&d1->d);
    free_measurement_data(&d2->d);
}
END_TEST

START_TEST(test_proc_environ_data)
{
    proc_env_meas_data *d1 = (proc_env_meas_data*)alloc_measurement_data(&proc_env_measurement_type);

    env_kv_entry *keyvaluepair1 = malloc(sizeof(env_kv_entry));
    fail_if(keyvaluepair1 == NULL, "Failed to create keyvalue pair");

    keyvaluepair1->key = strdup("USER");
    fail_if(keyvaluepair1->key == NULL, "Failed to create keyvalue pair");

    keyvaluepair1->value = strdup("UnitTest");
    fail_if(keyvaluepair1->value == NULL, "Failed to create keyvalue pair");

    env_kv_entry *keyvaluepair2 = malloc(sizeof(env_kv_entry));
    fail_if(keyvaluepair2 == NULL, "Failed to create keyvalue pair");

    keyvaluepair2->key = strdup("PATH");
    fail_if(keyvaluepair2->key == NULL, "Failed to create keyvalue pair");

    keyvaluepair2->value = strdup("/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:/home/usmdev/.local/bin:/home/usmdev/bin");
    fail_if(keyvaluepair2->value == NULL, "Failed to create keyvalue pair");

    d1->envpairs = g_list_append(d1->envpairs, keyvaluepair1);
    d1->envpairs = g_list_append(d1->envpairs, keyvaluepair2);

    proc_env_meas_data *d2 = (proc_env_meas_data*)do_serialize_unserialize(&d1->meas_data);

    GList *iter1, *iter2;
    for(iter1 = g_list_first(d1->envpairs), iter2 = g_list_first(d2->envpairs);
            iter1 != NULL && iter2 != NULL;
            iter1 = g_list_next(iter1), iter2 = g_list_next(iter2)) {

        env_kv_entry * ent1 = (env_kv_entry*)iter1->data;
        env_kv_entry * ent2 = (env_kv_entry*)iter2->data;

        fail_if(strcmp(ent1->key, ent2->key) != 0, "Key does not match %s != %s\n", ent1->key, ent2->key);
        fail_if(strcmp(ent1->value, ent2->value) != 0, "Value does not match %s != %s\n", ent1->value, ent2->value);
    }

    //Test Get Feature
    GList * pathsList = NULL;
    int featureSuccess = do_get_feature(&d1->meas_data, "var[PATH]", &pathsList);
    fail_if(featureSuccess != 0, "Get Feature Failed\n");

    GList * orgList = NULL;
    orgList = g_list_append(orgList, "/usr/local/bin");
    orgList = g_list_append(orgList, "/usr/local/sbin");
    orgList = g_list_append(orgList, "/usr/bin");
    orgList = g_list_append(orgList, "/usr/sbin");
    orgList = g_list_append(orgList, "/bin");
    orgList = g_list_append(orgList, "/sbin");
    orgList = g_list_append(orgList, "/home/usmdev/.local/bin");
    orgList = g_list_append(orgList, "/home/usmdev/bin");

    for(iter1 = g_list_first(orgList), iter2 = g_list_first(pathsList);
            iter1 != NULL && iter2 != NULL;
            iter1 = g_list_next(iter1), iter2 = g_list_next(iter2)) {

        fail_if(strcmp((char *) iter1->data, (char *)iter2->data) != 0, "Feature Values Mismatch %s != %s\n",
                (char *)iter1->data, (char *)iter2->data);
    }

    g_list_free(orgList);
    g_list_free(pathsList);

    free_measurement_data(&d1->meas_data);
    free_measurement_data(&d2->meas_data);
}
END_TEST

START_TEST(test_process_metadata)
{
    measurement_data *d1 = alloc_measurement_data(&process_metadata_measurement_type);
    process_metadata_measurement *md1 = container_of(d1, process_metadata_measurement, d);

    memcpy(md1->command_line,		"0123456789012345", 16);
    memcpy(md1->scheduling_class,	"0123456789012345", 16);
    memcpy(md1->start_time,		"0123456789012345", 16);
    memcpy(md1->tty,			"0123456789012345", 16);
    memcpy(md1->selinux_domain_label,	"0123456789012345", 16);

    md1->exec_time              = 12345679;
    md1->pid			= 12345;
    md1->ppid			= 45678;

    md1->user_ids.real		= 1357;
    md1->user_ids.effective    	= 1358;
    md1->user_ids.saved_set    	= 1359;
    md1->user_ids.filesystem   	= 1350;

    md1->group_ids.real		= 1357;
    md1->group_ids.effective   	= 1358;
    md1->group_ids.saved_set   	= 1359;
    md1->group_ids.filesystem  	= 1350;

    md1->exec_shield		= 9876;
    md1->loginuid		= 1123;
    md1->posix_capability	= 5813;
    md1->session_id		= 2134;

    measurement_data *d2 = do_serialize_unserialize(d1);
    process_metadata_measurement *md2 = container_of(d2, process_metadata_measurement, d);

    fail_if(memcmp(md1->command_line, md2->command_line,
                   sizeof(md1->command_line)) != 0,
            "Error field command_line mismatches. Expected %s but got %s",
            md1->command_line, md2->command_line);
    fail_if(md1->exec_time != md2->exec_time,
            "Error field exec_time mismatches. Expected %d but got %d",
            md1->exec_time, md2->exec_time);
    fail_if(memcmp(md1->scheduling_class, md2->scheduling_class,
                   sizeof(md1->scheduling_class)) != 0,
            "Error field scheduling_class mismatches. Expected %s but got %s",
            md1->scheduling_class, md2->scheduling_class);
    fail_if(memcmp(md1->start_time, md2->start_time,
                   sizeof(md1->start_time)) != 0,
            "Error field start_time mismatches. Expected %s but got %s",
            md1->start_time, md2->start_time);
    fail_if(memcmp(md1->tty, md2->tty,
                   sizeof(md1->tty)) != 0,
            "Error field tty mismatches. Expected %s but got %s",
            md1->tty, md2->tty);
    fail_if(memcmp(md1->selinux_domain_label, md2->selinux_domain_label,
                   sizeof(md1->selinux_domain_label)) != 0,
            "Error field selinux_domain_label mismatches. Expected %s but got %s",
            md1->selinux_domain_label, md2->selinux_domain_label);

    fail_if(md1->pid != md2->pid,
            "Error field pid mismatches. Expected %d but got %d\n",
            md1->pid, md2->pid);
    fail_if(md1->ppid != md2->ppid,
            "Error field ppid mismatches. Expected %d but got %d\n",
            md1->ppid, md2->ppid);
    fail_if(memcmp(&md1->user_ids, &md2->user_ids, sizeof(md1->user_ids)) != 0,
            "Error field user_id mismatches. Expected {%d,%d,%d,%d} but got {%d,%d,%d,%d}\n",
            md1->user_ids.real, md1->user_ids.effective, md1->user_ids.saved_set, md1->user_ids.filesystem,
            md2->user_ids.real, md2->user_ids.effective, md2->user_ids.saved_set, md1->user_ids.filesystem);
    fail_if(memcmp(&md1->group_ids, &md2->group_ids, sizeof(md1->group_ids)) != 0,
            "Error field group_id mismatches. Expected {%d,%d,%d,%d} but got {%d,%d,%d,%d}\n",
            md1->group_ids.real, md1->group_ids.effective,
            md1->group_ids.saved_set, md1->group_ids.filesystem,
            md2->group_ids.real, md2->group_ids.effective,
            md2->group_ids.saved_set, md1->group_ids.filesystem);

    fail_if(md1->exec_shield != md2->exec_shield,
            "Error field exec_shield mismatches. Expected %d but got %d\n",
            md1->exec_shield, md2->exec_shield);
    fail_if(md1->loginuid != md2->loginuid,
            "Error field loginuid mismatches. Expected %d but got %d\n",
            md1->loginuid, md2->loginuid);
    fail_if(md1->posix_capability != md2->posix_capability,
            "Error field posix_capability mismatches. Expected %d but got %d\n",
            md1->posix_capability, md2->posix_capability);
    fail_if(md1->session_id != md2->session_id,
            "Error field session_id mismatches. Expected %d but got %d\n",
            md1->session_id, md2->session_id);

    free_measurement_data(d1);
    free_measurement_data(d2);
}
END_TEST

START_TEST(test_namespaces_metadata)
{
    measurement_data *d1 = alloc_measurement_data(&namespaces_measurement_type);
    fail_if(d1 == NULL, "Failed to create namespaces measurement data");
    measurement_data *d2 = do_serialize_unserialize(d1);
    fail_if(d2 == NULL, "Failed to serialize/unserialize namespaces measurement data");
    free_measurement_data(d1);
    free_measurement_data(d2);
}
END_TEST

void setup(void)
{
    libmaat_init(0, 2);
}

void teardown(void)
{
    libmaat_exit();
}

int main(void)
{
    Suite *s;
    SRunner *sr;
    TCase *tcase;
    int number_failed;

    s = suite_create("Measurement Marshalling");
    tcase = tcase_create("Feature Tests");
    tcase_add_checked_fixture(tcase, setup, teardown);
    tcase_add_test(tcase, test_enumeration_data);
    tcase_add_test(tcase, test_filedata);
    tcase_add_test(tcase, test_filename_data);
    tcase_add_test(tcase, test_sha1_data);
    tcase_add_test(tcase, test_sha256_data);
    tcase_add_test(tcase, test_mtab_data);
    tcase_add_test(tcase, test_namespaces_metadata);
    tcase_add_test(tcase, file_metadata);
    tcase_add_test(tcase, test_report_data);
    tcase_add_test(tcase, test_path_list_data);
    tcase_add_test(tcase, test_elf_header_data);
    tcase_add_test(tcase, test_proc_environ_data);
    tcase_add_test(tcase, test_proc_root_data);
    tcase_add_test(tcase, test_process_metadata);
    suite_add_tcase(s, tcase);

    sr = srunner_create(s);
    srunner_set_log(sr, "test_measurement_marshalling.log");
    srunner_set_xml(sr, "test_measurement_marshalling.xml");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return number_failed;
}
