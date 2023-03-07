#!/usr/bin/env python3

#
# Copyright 2023 United States Government
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


import sys
import os.path
import re


base_path = os.path.dirname(os.path.abspath(__file__))

copyright_notice = """/*
 * Copyright 2023 United States Government
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
"""

def gen_measurement_type(name, magic):
    h_file_name = "%s_measurement_type.h" % name
    h_file_path = os.path.join(base_path, "measurement",
                               h_file_name)
    c_file_name = "%s_measurement_type.c" % name
    c_file_path = os.path.join(base_path, "measurement",
                               c_file_name)
    h_file = open(h_file_path, "w")

    args = {
        "copyright"   : copyright_notice,
        "h_file"      : h_file_name,
        "name"        : name,
        "upname"      : name.upper(),
        "magic"       : magic,
        "mtype"       : name+"_measurement_type",
        "dtype"       : name +"_data",

        "allocfun"    : "alloc_" + name + "_data",
        "copyfun"     : "copy_" + name + "_data",
        "freefun"     : "free_" + name + "_data",
        "serialfun"   : "serialize_" + name + "_data",
        "unserialfun" : "unserialize_" + name + "_data",
        "getattrfun"  : "get_attribute",        
    }
        
    h_file.write("""
%(copyright)s
#ifndef __%(upname)s_MEASUREMENT_TYPE_H__
#define __%(upname)s_MEASUREMENT_TYPE_H__

#include <graph/graph-core.h>

#define %(upname)s_MEASUREMENT_TYPE_MAGIC (0x%(magic)X)
#define %(upname)s_MEASUREMENT_TYPE_NAME "%(name)s"

/**
 * FIXME: Documentation of %(dtype)s measurement_data.
 * Represents FOO
 * Supports attributes X, Y, Z
 * Supports custom predicates P, Q
 */
typedef struct %(dtype)s {
\tmeasurement_data d;
\t/* FIXME: custom fields here */
} %(dtype)s;

/* FIXME: Define custom methods */

extern measurement_type %(mtype)s;
#endif
""" % args)

    h_file.close()

    c_file = open(c_file_path, "w")

    c_file.write("""
%(copyright)s
#include <util/util.h>
#include <stdlib.h>
#include <errno.h>
#include <graph/graph-core.h>
#include <%(h_file)s>

static measurement_data *%(allocfun)s(void)
{
\t%(dtype)s *ret;

\tret = (%(dtype)s *)malloc(sizeof(*ret));
\tif(ret == NULL) {
\t\treturn NULL;
\t}
\tbzero(ret, sizeof(*ret));
\t/* FIXME: initialize custom fields */
\treturn (measurement_data *)ret;
}

static measurement_data *%(copyfun)s(measurement_data *d)
{
\t%(dtype)s *dd  = (%(dtype)s *)d;
\t%(dtype)s *ret = (typeof(ret))alloc_measurement_data(&%(mtype)s);

\tif(ret == NULL) {
\t\treturn NULL;
\t}

\t /* FIXME: copy custom fields */

\treturn (measurement_data*)ret;
}

static void %(freefun)s(measurement_data *d)
{
\t%(dtype)s *dd = (%(dtype)s *)d;
\tif(dd != NULL) {
\t\t/* FIXME: free custom fields */
\t\tfree(dd);
\t}

\treturn;
}

static int %(serialfun)s(measurement_data *d, char **serial_data, size_t *serial_data_size)
{
\t%(dtype)s *dd = (%(dtype)s *)d;
\t/* FIXME: serialize fields */
\treturn -ENOSYS;
}

static int %(unserialfun)s(char *sd, size_t sd_size, measurement_data **d)
{
\t /* FIXME: unserialize fields */
\t return -ENOSYS;
}

static int %(getattrfun)s(measurement_data *d, char *attribute, GList **out)
{
\t /* FIXME: get attribute */
\t return -ENOENT;
}

/* FIXME: Implement custom methods */

measurement_type %(mtype)s = {
\t.name                    = %(upname)s_MEASUREMENT_TYPE_NAME,
\t.magic                   = %(upname)s_MEASUREMENT_TYPE_MAGIC,
\t.alloc_data              = %(allocfun)s,
\t.copy_data               = %(copyfun)s,
\t.free_data               = %(freefun)s,
\t.serialize_data          = %(serialfun)s,
\t.unserialize_data        = %(unserialfun)s,
\t.get_attribute           = %(getattrfun)s
};
""" % args)
    c_file.close()

    print("Generated skeletal measurement type.")
    print("Be sure to fill in your custom type definitions.")
    print("\t" + h_file_path)
    print("\t" + c_file_path)
    print("And register your type in measurement-types.h")
    print("And add compilation directives to Makefile.am")
    
def gen_address_space(name, magic):
    h_file_name = "%s_address_space.h" % name
    h_file_path = os.path.join(base_path, "address_space",
                               h_file_name)
    c_file_name = "%s_address_space.c" % name
    c_file_path = os.path.join(base_path, "address_space",
                               c_file_name)
    h_file = open(h_file_path, "w")

    args = {
        "copyright"    : copyright_notice,
        "h_file"       : h_file_name,
        "name"         : name,
        "upname"       : name.upper(),
        "magic"        : magic,
        "space"        : name+"_address_space",
        "atype"        : name +"_address",

        "allocfun"     : "alloc_" + name + "_address",
        "copyfun"      : "copy_" + name + "_address",
        "freefun"      : "free_" + name + "_address",
        "coercefun"    : "coerce_" + name + "_address",        
        "serialfun"    : "serialize_" + name + "_address",
        "unserialfun"  : "unserialize_" + name + "_adddress",
        "toasciifun"   : name + "_address_to_ascii",
        "fromasciifun" : name + "_address_from_ascii",
        "equalfun"     : name + "_address_equal",
        "hashfun"      : "hash_"+name+"_address",
        "readfun"      : name + "_read_bytes",
    }
        
    h_file.write("""%(copyright)s
#ifndef __%(upname)s_ADDRESS_SPACE_H__
#define __%(upname)s_ADDRESS_SPACE_H__

/*! \file
 * FIXME: describe this file
 */
#include <graph/graph-core.h>

#define %(upname)s_ADDRESS_SPACE_MAGIC (0x%(magic)X)
#define %(upname)s_ADDRESS_SPACE_NAME "%(name)s"

/**
 * FIXME: describe the addres space
 */
typedef struct %(atype)s {
\taddress a;
\t/* FIXME: Add custom fields here */
} %(atype)s;

/* FIXME: Add custom methods here */

extern struct address_space %(space)s;
#endif
""" % args)

    h_file.close()

    c_file = open(c_file_path, "w")

    c_file.write("""%(copyright)s
#include <errno.h>
#include <stdlib.h>
#include <graph/graph-core.h>
#include <%(h_file)s>

static address *%(allocfun)s()
{
\t%(atype)s *res;
\tres = (%(atype)s *)malloc(sizeof(%(atype)s));
\tif(res == NULL) {
\t\treturn NULL;
\t}

\tbzero(res, sizeof(*res));
\t /* FIXME: Initialize custom fields */
\treturn &res->a;
\t}

static void %(freefun)s(address *a)
{
\t%(atype)s *aa = (%(atype)s*)a;
\t/* FIXME: Free custom fields */
\tfree(aa);
\treturn;
}

static address *%(coercefun)s(address *from)
{
\t/* FIXME: Implement coercion for supported source spaces */
\treturn NULL;
}

static address *%(copyfun)s(address *a)
{
\t%(atype)s *orign = (%(atype)s *)a;
\t%(atype)s *copy  = (%(atype)s *)alloc_address(&%(space)s);
\tif(copy == NULL) {
\t\treturn NULL;
\t}

\t/* FIXME: Copy custom fields */
\treturn &copy->a;
}

static char *%(serialfun)s(address *a)
{
\t%(atype)s *orig = (%(atype)s *)a;
\t/* FIXME: implement serialization */
\treturn NULL;
}

static address *%(unserialfun)s(char *buf, size_t len)
{
\t/* FIXME: implement deserializaiton */
\treturn NULL;
}

static char *%(toasciifun)s(address *a)
{
\t%(atype)s *orig = (%(atype)s *)a;
\t/* FIXME: implement human readable serialization */
\treturn NULL;
}

static address *%(fromasciifun)s(char *str)
{
\t/* FIXME: implement parsing human readable */
\treturn NULL;
}

static gboolean %(equalfun)s(const address *a, const address *b)
{
\t%(atype)s *orig_a = (%(atype)s *)a;
\t%(atype)s *orig_b = (%(atype)s *)b;

\t/* FIXME: implement equality testing */

\treturn FALSE;
}

static guint %(hashfun)s(const address *a)
{
\t%(atype)s *orig_a = (%(atype)s *)a;
\t/* FIXME: implement a hash function */
\treturn 0;
}

static void *%(readfun)s(address *a, size_t sz)
{
\t/* FIXME: read some bytes. */
\treturn NULL;
}

struct address_space %(space)s = {
\t.magic               = %(upname)s_ADDRESS_SPACE_MAGIC,
\t.alloc_address       = %(allocfun)s,
\t.free_address        = %(freefun)s,
\t.coerce_address	   = %(coercefun)s,
\t.copy_address        = %(copyfun)s,
\t.serialize_address   = %(serialfun)s,
\t.parse_address	   = %(unserialfun)s,
\t.human_readable	   = %(toasciifun)s,
\t.from_human_readable = %(fromasciifun)s,
\t.address_equal	   = %(equalfun)s,
\t.address_hash        = %(hashfun)s,
\t.read_bytes		   = %(readfun)s,
};

""" % args)

    c_file.close()
    
    print("Generated skeletal address space.")
    print("Be sure to fill in your custom type definitions.")
    print("\t" + h_file_path)
    print("\t" + c_file_path)
    print("And register your type in address-spaces.h")
    print("And add compilation directives to Makefile.am")


def gen_target_type(name, magic):
    h_file_name = "%s_target_type.h" % name
    h_file_path = os.path.join(base_path, "target",
                               h_file_name)
    c_file_name = "%s_target_type.c" % name
    c_file_path = os.path.join(base_path, "target",
                               c_file_name)
    h_file = open(h_file_path, "w")

    args = {
        "copyright"    : copyright_notice,
        "h_file"       : h_file_name,
        "name"         : name,
        "upname"       : name.upper(),
        "magic"        : magic,
        "ttype"        : name+"_target_type",

        "readfun"      : name + "_read_instance",
    }
        
    h_file.write("""%(copyright)s
#ifndef __%(upname)s_TARGET_TYPE_H__
#define __%(upname)s_TARGET_TYPE_H__

/*! \\file
 * FIXME: Describe the target type defined by this file.
 */
 
#include <graph/graph-core.h>

#define %(upname)s_TARGET_TYPE_NAME "%(name)s"
#define %(upname)s_TARGET_TYPE_MAGIC (0x%(magic)X)

extern target_type %(ttype)s;

#endif

""" % args)

    h_file.close()

    c_file = open(c_file_path, "w")
    c_file.write("""%(copyright)s

#include <graph/graph-core.h>
#include <%(h_file)s>

static void *%(readfun)s(target_type *type, address *a, size_t *size)
{
\t/* FIXME: What is this even supposed to do? */
\treturn NULL;
}

struct target_type %(ttype)s = {
\t.magic         = %(upname)s_TARGET_TYPE_MAGIC,
\t.name          = %(upname)s_TARGET_TYPE_NAME,
\t.read_instance = %(readfun)s
};
""" % args)
    c_file.close()
  
    print("Generated skeletal target type.")
    print("Be sure to fill in your custom type definitions.")
    print("\t" + h_file_path)
    print("\t" + c_file_path)
    print("And register your type in target_types.h")
    print("And add compilation directives to Makefile.am")


kinds = {
    "measurement" : gen_measurement_type,
    "address"     : gen_address_space,
    "target"      : gen_target_type,
    }
    
if __name__ == "__main__":

    if len(sys.argv) != 4:
        print("Usage: %s <kind> <name> <magic>" % (sys.argv[0]))
        print("\tkind ::= %s" % (str.join(" | ", kinds.keys())))
        exit()

    kind  = sys.argv[1]

    if kind not in kinds:
        print("Error: kind must be in {%s} got \"%s\"" % (str.join(", ", kinds.keys()), kind))
        exit()
        
    name  = sys.argv[2]

    if not re.match("^[a-zA-Z_][a-zA-Z0-9_]*$", name):
        print("Error: name must be a valid C identifier.")
        exit()
        
    try:
        magic = int(sys.argv[3], 16)
    except:
        print("Magic number must be a hexadecimal number (got \"%s\")" % sys.argv[3])
        exit()

    print("Generating %s named %s with magic %X\n" % (kind, name, magic))


    kinds[kind](name, magic)
        
