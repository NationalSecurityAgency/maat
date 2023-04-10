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
#

#
# utils.py functions for attribute parsing and sanitization used by 
# scripts for adding machines and resources to database
# 

# Parse any additional attributes passed in as JSON
# Skips any attributes that already have a value to avoid
# overwriting. Double check to make sure not trying to 
# overwrite _id field. 
def parse_extra(db_entry, extra_dict) :
    for attribute in extra_dict :
        if (attribute not in db_entry.keys()) and (attribute != "_id"):
            db_entry[attribute] = extra_dict[attribute]
    return db_entry

# checks all keys and values for HTML
def dict_contains_html(dictionary):
    for key, value in dictionary.items():
        if (string_contains_html(key) or string_contains_html(value)):
            return True
    return False

# Basic check for dirty input
# XXX: May want to switch to a library that actually pulls
# out text instead of just reporting an error.
def string_contains_html(string) :
    if '&' in string: return True;
    if '<' in string: return True;
    if '>' in string: return True;
    if '"' in string: return True;
    if "'" in string: return True;
    if "/" in string: return True;

    return False
