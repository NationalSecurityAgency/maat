COPYRIGHT
=========

Copyright 2020 United States Government

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

About
=====

*EXPERIMENTAL* OCaml tool to take an Copland-based s-expression as input, 
and output an APB that implements the s-expression input. This is 
intended to be close to how we might actually implement Copland 
evaluation in an APB, but high level enough that it is still easy to 
experiment with. The end goal here would be to have APBs that can be 
proven to implement the Copland phrase that they claim to implement in 
their xml.in file. 

Note, this is reference code, so it likely has many bugs. Notably,
file descriptors are leaked into child processes and exceptions are
completely ignored.

Dependencies
============

Requires the Core, Yojson, PPX Let, PPX SEXP Conv, PPX Deriving, xmlm, and
PPX Deriving Yojson packages. 

```
   opam install core yojson ppx_deriving_yojson ppx_sexp_conv xmlm
```

_Note_: There have been some compatibility issues with `ppx_sexp_conv`
and `ppx_deriving` with `ppx_type_conv` version `v0.9.1`. Upgrading to
ocaml `4.05.0` with `ppx_type_conv` version `v0.10.0` seems to work.

Building
========

You can build the example workflow interpreter using the `make` command: 
```
   make
```

Real APB Example (Work in Progress)
===================================

This will use the 'standard ASPS' in Maat (serialize graph, compress, encrypt,
create contract, and send) to serialize and relay an existing Maat graph to a
pipe.

1. Install Maat with the configuration option `--prefix=/opt/maat`
2. Rename the hardcoded graph path in stdasps.sexp to a leftover maat graph
   on your system (graphs should remain in `/tmp/` after running through the
   tutorial). Copy the example execute contract (execute_contract.xml) to
   /tmp/workdir (hardcoded work directory ASPs will use, execute contract is
   needed for the create_contract ASP).
   ```
      sudo mkdir /tmp/workdir
      sudo cp execute_contract.xml /tmp/workdir/
   ```   
   
3. Build the compiler and generate the C source code and APB XML based upon the
   S-Expression in stdasps.sexp

```
   make
   ./workflow.native -c stdasps.c -s stdasps.sexp
   ./workflow.native -x stdasps.xml.in -s stdasps.sexp
```

4. Edit the placeholders in stdasps.xml.in to add information about the APB.
   Adding at least one supported Copland phrase is a requirement, as well as
   UUIDs which correspond to the ASPs you are calling

5. Add the .xml.in and .c file to the `~/maat/src/apbs` directory and add a 
   reference to the APB to `~/maat/src/apbs/Makefile.am` so that the APB will be
   built

6. Add the APB to the DEFAULT_APB list in `~/maat/configure.ac`

At this point, if you follow the instructions to configure and build Maat, your 
APB will be available and can be negotiated over using the Copland phrases you 
added to `stdasps.xml.in`.

For more information about adding an APB to Maat, please consult 
`~/maat/src/apbs/README.md`

Correspondence with Copland Terms
=========================

The `workflow` type defined here is intended to correspond with the structures 
of Copland terms with the semantics provided by the `run` function.
The primary difference is that:
1. Remote subterms are assumed to be encapsulated in a single ASP
   action
2. The dataflow between atomic terms is explicitly constructed using
   file descriptors to pass evidence to or around components

To support (2) explicit `split` and `merge` operations are required
for both `Parallel` and `Sequential` composition.

If terms are combined via `Sequential` or `Parallel`, the dataflow
must be split: a subset of the current input is passed to each of the
two subterms, and merged: the output of the two subterms is combined
to a new output. This allows implementation of the abstract `par` and
`seq` functions used to combine evidence in the evidence semantics of
Copland.

The difference between `Sequential` and `Parallel` is that the first
subterm of `Sequential` is executed to completion prior to executing
the first subterm of `Parallel`. This reflects the difference between
`;` and `||` in Copland.

The `Pipeline` constructor supports dataflow where input from one
subterm is passed to another (e.g., for the `ENV` action). This is a
form of parallel composition because the subterms are executed
concurrently, but internal synchronization (e.g., blocking for input)
may ensure sequencing properties.

The `Serial` constructor is similar to `Pipeline` but inserts a
buffering subprocess that ensures the left subflow terminates before
the execution of the right subflow. The `Serial` constructor should
correspond exactly to `;` in Copland.

Handling Serial
===============

The interpreter and compiler handle the `Serial` construct somewhat
differently.

The interpreter relies on its ability to serialize and interpret
workflows to pass the righthand flow to another instance of itself. It
treats `Serial a b` as syntactic sugar for `Pipeline a (ASP self
["-b"; "-s"; "-e"; sexp_of_workflow b])`. This causes the interpreter
to fork another version of itself in a buffering mode, the buffering
interprter will read its input to EOF, set up a new pipe, then fork
again. The child of the bufferer sets the read end of the new pipe as
its standard input and interprets its workflow argument, the bufferer
writes the buffered input to the pipe then waits for its child to
exit. The ASCII art diagram below reflects these flows, each column
represents a separate process.

<pre>
original --- fork/exec ---> buffer
   |                          |
   |                      read input
   |                          |
   |                          +------ fork --------> child
   |                          |                        |
   |                          |                        |
   |                     write buffer -- pipe --> interpret b
   |                          |                        |
   |                          |                        |
   |                        wait <------------------ exit
   |                          |
   |                          |
 wait <-------------------- exit
</pre>

The compiler can't play the same game because it can't rely on runtime
serialization and interpretation of workflows. Instead, it uses a
`fork_and_buffer()` primitive function defined in `runasp.c` to
implement the buffering semantics and inlines the righthand flow into
the body of the generated code inside a block that will be executed by
a subprocess `fork()`ed (but not `exec()`ed) from within
`fork_and_buffer()`.

The `fork_and_buffer()` routine actually performs two `fork()`
operations. First, it `fork()`s from the orignal process and reads
input to `EOF` in the child. Then, it `fork()`s again and uses the
original child to write the buffered input to a pipe connected to the
grandchild. In the original process, control is returned back to the
main function with a return value of `0` which will cause the
execution to skip over the righthand subflow and continue dispatching
work as normal. In the grandchild process, `fork_and_buffer()` returns
back to the main function with a return value `> 0` which causes the
righthand subflow to be executed. In the child process,
`fork_and_buffer()` never returns, it writes the buffered input data
then `exit()`s.

The `main` function ends up looking something like:

```
	pid_t child;
	int infd;
	rc = fork_and_buffer(&child, &infd, ...);
	if(rc > 0){
		...	
		/* do_subflow_b with stdin <- infd */
		...
		return 0; /* exits the program */
		...
		*cleanups*
		...
	}
	...
	/* rest of the workflow */
	...
```

The flow looks essentially the same as the interpreter case:

<pre>
original --- fork --------> child
   |                          |
   |                      read input
   |                          |
   |                          +------ fork ------> grandchild
   |                          |                        |
   |                          |                        |
   |                     write buffer <--- pipe --- execute b
   |                          |                        |
   |                          |                        |
   |                        wait <------------------ exit
   |                          |
   |                          |
 wait <-------------------- exit
</pre>
