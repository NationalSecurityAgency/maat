<!--
Copyright 2023 United States Government

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. 
-->

ASP Developer Guide
===================

Making a New ASP
----------------

To write and integrate an ASP you need to create and modify several files.

    1. Follow `asp_skeleton.c` to develop the core functionality of your ASP.
        a. Add this file to `maat/src/asps/Makefile.am`
        b. Add the ASP's name to the `maat/configure.ac` file
    1. Follow `asp_skeleton.xml.in` to describe the operation of your ASP and provide
       it with a unique uuid.
        a. Add appropriate documentation for your ASP in `maat/documentation/`
    1. Specify the selinux policy for your ASP in `maat/selinux/maat.te` and
       `maat/selinux/maat.fc.in`

Packaging
---------

- Add the ASP to `rpm/maat.spec`

Testing
-------

- Create a test file for your ASP in `maat/src/test/`
- Add the new test file to `maat/src/test/Makefile.am`
