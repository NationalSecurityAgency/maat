COPYRIGHT
=========

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

Dependencies
============

Requires the Core, Yojson, PPX Let, PPX SEXP Conv, PPX Deriving, xmlm, Menhir and
PPX Deriving Yojson packages as well as the Dune build system. 

```
   opam install core yojson ppx_deriving_yojson ppx_sexp_conv xmlm
```

Building
========

You can build the compiler using the `dune build` command:

```
   dune build
```
This will produce an executable in `_build/default/bin/main.exe`

Running
========
The compiler will compile a copland phrase present in the file provided with the `-f` flag.
The parser was designed to parse Copland phrases as typically written.
For further inspection or development see `lib/lexer.mll` and `lib/parser.mly`.
Example copland phrases can be found in `examples/*.cl` files.

Each ASP in the compiled ASP can be run on a batch of arguments.
These arguments are provided in an arguments file specified with the `-a` flag.
These files have the following format.
```
(
   arg_name1 (file1 ... filen)
   ...
   arg_namen (file1 ... filen)   
)
```
Alternatively, an argument name can be mapped to the special identifier `children`, which refers to new nodes produced by the previous ASP that was run.
For example, after running `listdirectoryserviceasp`, you could run `hashfileserviceasp` on `children`, and hash each node that was created during the running of `listdirectoryserviceasp`.


Examples can be found in `examples/*.args`


You can run the compiler with the following command.
```
./main.exe -f <copland phrase file> -a <argument map file> -c <output c file name>
```

If you are developing compiler, it is useful to be able to run the compiler without building and retrieving the executable, this can be accomplished with the following command.
```
dune exec -- copland_compiler -f <copland phrase file> -a <argument map file> -c <output c file name>
```

Please see the general MAAT documentation on how to properly build and use APBs.
Please not that this compiler is experimental, and its output has not been as thoroughly tested as the core functionality of MAAT.

ASP XML File
=========

In order to compile an ASP, there must be an accompanying `.xml` file that contains some essential information.
These xml files should be located in a directory that can be specified with the `-d` flag.
This xml file should contain the `<name>`, `<uuid>`, `target_type`, and `address_type` of the asp.
The information in these tags is necessary for the compiler to function on that asp.
The `<name>` and `<uuid>` tags should be top-level children of an `<asp>` tag.
The `target_type` and `address_type` information should be attributes of the `<capability>` tag, which is the child of `<satisfier>` which is in turn a child of `<measurers>`.

This structure is specified in this partial xml.
```
<asp>
   <name>name</name>
   <uuid>uuid<uuid>
   ...
   <measurers>
      <satisfier>
         <capability target_type="target_type" address_type="address_type" .../>
      </satisfier>
   </measurers>
   ...
</asp>
```


The following xml is a more complete example of a valid asp xml file.
```
<asp>
	<name>hashfileservice</name>
	<uuid>dff44141-9d3a-4cfe-8a30-2c072bb77025</uuid>
	<type>File</type>
	<description>SHA1 hash of target file</description>
	<usage>
        hashfileservice [graph path] [node id]</usage>
	<inputdescription>...</inputdescription>
	<outputdescription>...</outputdescription>
	<seealso>
        sha1</seealso>
	<example>
	...
	<aspfile hash="XXXXXX">/opt/maat/lib/maat/asps/hashfileserviceasp</aspfile>
	<measurers>
		<satisfier id="0">
			<value name="type">HASHFILE</value>
                        <capability target_type="file_target_type" target_magic="1001" target_desc = "..." 
				address_type="file_addr_space" address_magic="0x5F5F5F5F" address_desc = "A..."
				measurement_type="sha1hash_measurement_type" measurement_magic="3100" measurement_desc = "..."/>
		</satisfier>
	</measurers>
	<security_context>
	  <selinux><type>hash_file_service_asp_t</type></selinux>
	  <user>maat</user>
	  <group>maat</group>
	</security_context>
</asp>

```

Current Limitations
=========

- The compiler does not support running APBs at remote locations. The compiler assumes all Copland phrases do not use the @ constructor.

- This compiler does not currently support ASPs that communicate using pipes. This includes both input and output. In particular, if you want to write an APB that ends by sending the measurement graph through an output channel without signing it, you would need to write additional code to implement this behavior.

- This compiler relies on `target_type` and `address_type` information present in the asp `.xml` files. Not all of the `.xml` files are properly formatted for the copland compiler to parse this information.

- Different ASPs require different code to generate measurement variables. For the examples we have handled so far, the `address_type` provides enough information to perform this task correctly. ASPs that we have not yet handled may require more information.

