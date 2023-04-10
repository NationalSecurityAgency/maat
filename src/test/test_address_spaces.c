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
#include <util/util.h>
#include <maat-basetypes.h>

void test_equal_reflexive(address *a)
{
    fail_unless(address_equal(a, a),
                "Address in space %08x is not equal to itself.",
                a->space->magic);
}

void test_copy_equal(address *a)
{
    address *b = copy_address(a);
    fail_if(b == NULL, "Failed to copy address in space %08x.", a->space->magic);
    fail_unless(address_equal(a, b),
                "Copy of address in space %08x is not equal to original.",
                a->space->magic);
    free_address(b);
}

void test_serialize_equal(address *a)
{
    char *serialized = serialize_address(a);
    fail_if(serialized == NULL, "Failed to serialize address in space %08x.",
            a->space->magic);
    address *b = parse_address(a->space, serialized, strlen(serialized)+1);
    fail_if(b == NULL, "Failed to parse serialized address %s in space %08x.",
            serialized, a->space->magic);
    fail_unless(address_equal(a, b),
                "Unserialized address is not equal to original in space %08x.",
                a->space->magic);
    free(serialized);
    free_address(b);
}

START_TEST(test_pid_as)
{
    struct pid_address *addr = (struct pid_address*)alloc_address(&pid_address_space);
    fail_if(addr == NULL, "Failed to allocate pid address.");
    addr->pid = random();
    test_equal_reflexive(&addr->a);
    test_copy_equal(&addr->a);
    test_serialize_equal(&addr->a);
    free_address(&addr->a);
}
END_TEST

START_TEST(test_file_as)
{
    file_addr *addr = (file_addr*)alloc_address(&file_addr_space);
    size_t path_size = random() % 32768;
    int i;
    fail_if(addr == NULL, "Failed to allocate pid address.");

    addr->fullpath_file_name = malloc(path_size);
    fail_if(addr->fullpath_file_name == NULL,
            "Failed to allocate filename of length %u. For file address.",
            path_size);
    for(i=0; i<path_size-1; i++) {
        addr->fullpath_file_name[i] = 'a' + (random() % 26);
    }
    addr->fullpath_file_name[path_size-1] = '\0';

    addr->device_major = random();
    addr->device_minor = random();
    addr->file_size    = random();
    addr->node         = random();

    test_equal_reflexive(&addr->address);
    test_copy_equal(&addr->address);
    test_serialize_equal(&addr->address);
    free_address(&addr->address);
}
END_TEST

START_TEST(test_simple_file_as)
{
    simple_file_address *addr = (simple_file_address*)alloc_address(&simple_file_address_space);
    size_t filename_size = random() % 32768;
    int i;
    fail_if(addr == NULL, "Failed to allocate simple file address.");

    addr->filename = malloc(filename_size);
    fail_if(addr->filename == NULL,
            "Failed to allocate filename of size %u. For simple_file address.",
            filename_size);
    for(i=0; i<filename_size-1; i++) {
        addr->filename[i] = 'a' + (random() % 26);
    }
    addr->filename[filename_size-1] = '\0';

    test_equal_reflexive(&addr->a);
    test_copy_equal(&addr->a);
    test_serialize_equal(&addr->a);
    free_address(&addr->a);
}
END_TEST

START_TEST(test_package_as)
{
    package_address *addr = (package_address*)alloc_address(&package_address_space);
    size_t attr_size = random() % 32768;
    int i;
    fail_if(addr == NULL, "Failed to allocate package address.");

    addr->name = malloc(attr_size);
    fail_if(addr->name == NULL, "Failed to allocate package name of size %u for package address.", attr_size);

    addr->version = malloc(attr_size);
    fail_if(addr->version == NULL, "Failed to allocate package version of size %u for package address.", attr_size);

    addr->arch = malloc(attr_size);
    fail_if(addr->arch == NULL, "Failed to allocate package arch of size %u for package address.", attr_size);

    for(i = 0; i < attr_size-1; i++) {
        addr->name[i]    = 'a' + (random() % 26);
        addr->version[i] = 'a' + (random() % 26);
        addr->arch[i]    = 'a' + (random() % 26);
    }
    addr->name[attr_size-1]    = '\0';
    addr->version[attr_size-1] = '\0';
    addr->arch[attr_size-1]    = '\0';

    test_equal_reflexive(&addr->a);
    test_copy_equal(&addr->a);
    test_serialize_equal(&addr->a);
    free_address(&addr->a);
}
END_TEST

START_TEST(test_inode_as)
{
    address *addr = alloc_address(&inode_address_space);
    fail_if(addr == NULL, "Failed to allocate inode address.");
    inode_address *iaddr = container_of(addr, inode_address, a);
    iaddr->inum = random();
    test_equal_reflexive(addr);
    test_copy_equal(addr);
    test_serialize_equal(addr);
    free_address(addr);
}
END_TEST

START_TEST(test_file_region_as)
{
    address *addr = alloc_address(&file_region_address_space);
    fail_if(addr == NULL, "Failed to allocate file region address.");
    file_region_address *fra = container_of(addr, file_region_address, a);
    fra->path = malloc(256);
    int i;
    for(i=1; i<=255; i++) {
        fra->path[i-1] = i;
    }
    fra->path[255] = '\0';

    fra->offset = random();
    fra->sz     = random();
    test_equal_reflexive(addr);
    test_copy_equal(addr);
    test_serialize_equal(addr);
    free_address(addr);
}
END_TEST

void setup(void)
{
    libmaat_init(0, 2);
}

void teardown(void)
{
}

int main(void)
{
    Suite *s;
    SRunner *sr;
    TCase *tcase;
    int number_failed;

    s = suite_create("Address Spaces");
    tcase = tcase_create("Feature Tests");
    tcase_add_checked_fixture(tcase, setup, teardown);
    tcase_add_test(tcase, test_pid_as);
    tcase_add_test(tcase, test_file_as);
    tcase_add_test(tcase, test_simple_file_as);
    tcase_add_test(tcase, test_package_as);
    tcase_add_test(tcase, test_inode_as);
    tcase_add_test(tcase, test_file_region_as);
    suite_add_tcase(s, tcase);

    sr = srunner_create(s);
    srunner_set_log(sr, "test_address_spaces.log");
    srunner_set_xml(sr, "test_address_spaces.xml");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return number_failed;
}
