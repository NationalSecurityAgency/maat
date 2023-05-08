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

APB Developer Guide
===================

APB .xml.in
-----------

The purpose of this file is to provide the basic details of the APB and how it interacts with other
components. The file includes - but is not limited to - the following sections:

### ASP

The ASP section of the file enumerates the ASPs the APB uses. An APB should only invoke ASPs
which are declared in the file. This is specified in the file as follows, with the ellipses filled
in as appropriate:

.. code-block:: xml

    <asps>
        <asp uuid="..." initial="True">...</asp>
        ...
    </asps>

### Copland

The Copland section of the file specifies Copland phrases that are handled by the APBs. Each Copland
section in the file specifies one Copland phrase supported by the APB, the measurement specification
used in the execution of the phrase, and any arguments the phrase may possess.

Currently, there are no specific programmatic constraints on how a phrase is named, but in general phrases
should conform with Copland syntax.

Copland phrases are specified in the file as follows, with the ellipses filled in as appropriate:

.. code-block:: xml

    <copland>
        <phrase copland="...">...</phrase>
        <spec uuid="...">...</spec>
        <args>...</args>
        <places>...</places>
    </copland>

The `copland` field holds the Copland phrase which this Copland block represents.

The `spec` field, which specifies the measurement specification that is used when the APB executes this
Copland phrase, is optional and can be omitted if no measurement specification will be used when this
phrase is selected.

Copland phrases can specify the name, type and number of arguments that it requires, if any. Each
argument for the phrase is specified within its own argument section within the `args` section of the
prior XML. If a Copland phrase supports no arguments, then the args section can be omitted entirely. The
argument sections are laid out as follows, with the ellipses filled in as appropriate:

.. code-block:: xml

    <arguments>
        <arg name = "...">
            <type> ... </type>
        </arg>
        ...
    </arguments>

Currently Copland supports integer, string, and place arguments.

If at least one argument with a place type is specified, then a places section is required. The places section
is layed out as follows:

.. code-block:: xml

    <places>
        <place id="@_1">
            <info>host</info>
            <info>port</info>
	        ...
        </place>
        ...
    </places>

For each place argument specified in the arguments section, there must be a corresponding place subsection
of the places section. The id MUST correspond to the name provided in the arg section for the argument.
Within the place section, there are info sections which specify what information the APB should have
knowledge pertaining the specified place. The following pieces of information are currently supported:

1. host - the IP address of the place's attestation manager
2. port - the port on which the place's attestation manager listens
3. kernel - the version of the kernel running at the place
4. domain - the Xen domain ID of a place (if it is running in a domain)

An example of a complete Copland section is as follows:

.. code-block:: xml

    <copland>
        <phrase copland="(USM hash file iterations)">hash file measurement</phrase>
        <spec uuid="d427cbfa-252f-4b81-9129-8f436d9172f8">hash spec</spec>
        <arguments>
            <arg name = "file">
                <type>string</type>
            </arg>
            <arg name = "iterations">
                <type>integer</type>
            </arg>
            <arg name = "@_1">
                <type>place</type>
            </arg>
        </arguments>
        <places>
            <place id="@_1">
                <info>host</info>
                <info>port</info>
            </place>
        </places>
    </copland>

This example Copland section specifies a Copland phrase (USM hash file iterations) that takes three
arguments - one is named "file" and is of the string type, another is named "iterations" and has an
integer type, and the third is named "@_1" and corresponds to a Copland place of which the executing
attestation manager may have information regarding. Based on the places section which appears after the
arguments section, the host IP and port number of the "@_1" place will be made available to the APB.
The measurement specification with the specified UUID will be used when invoking the APB with this
phrase. Note that the text within the `spec` section is not used by Maat, and can be thought of as an
annotation for the identity of the measurement specification.

In order to be used in negotiation by an attestation manager, the `apb_phrase` field in the relevant
`condition` field in the selector policy should match the contents of the `phrase` XML section. For more
information about how to incorporate Copland phrases into selector policies, please consult the
documentation relevant to selectors and selector policy.

### File

The file section of the file declares the executable that is actually invoked when your APB is executed.
Files are specified as follows, with the ellipses as appropriate:

.. code-block:: xml

    <file hash="...">${APB_INSTALL_DIR}/...</file>

Most APBs should be installed to the APB install directory (the location of which is defined in
${APB_INSTALL_DIR}) and so a location within that directory is generally advised. However, if there is a
reason for the APB executable to be located other location (such as using an APB executable that is not
compiled with the rest of Maat), then the specific executable location can be specified.

### Name

The name section of the APB, as the name implies, declares the name of the APB. The name is specified as
follows, with the ellipses specified as appropriate:

.. code-block:: xml

    <name>...</name>

This name is used in Maat to help identify your APB, primarily in debug statements.

As will become clear in future sections, you will need to maintain a consistent name for your APB, and
declaring it in the XML section can be a practical way to keep track of that information.

APB .c
-------

APBs are flexible representations of measurement functionality designed to accommodate diverse
measurement applications. They control how ASPs are applied to measurement targets and how
measurements are combined. This is the source file which specifies the behavior of the APB.

### apb_execute

`apb_execute` is the function that is called in order to execute the functionality of an APB compiled
with Maat and its libraries. If your executable requires any Maat functions it must implement this
function at a minimum. The function should return a zero for successful execution and a non-zero integer
otherwise.

The signature of the `apb_execute` function is as follows:

.. code-block:: c

    int apb_execute(struct apb *apb, struct scenario *scen, uuid_t meas_spec_uuid,
                    int peerchan, int resultchan, char *target, char *target_type,
                    char *resource, struct key_value **arg_list, int argc);


The arguments provided by to this function contain the following information:

* `apb` - contains information about an APB such as the ASPs available to it for execution, its UUID, and
  more (for more details, consult the struct definition in `lib/common/apb_info.h`).
* `scen` - contains information regarding the negotiation between the Attester and Appraiser such as the
  keys and certificates used during negotiation and the nonce for this measurement.
* `meas_spec_uuid` - contains the UUID of the measurement spec that is being used for this execution of
  the APB.
* `peerchan` - file descriptor referring to the channel of communication to a peer (usually the
  appraiser), which is normally used to transfer measurements from the attester to the appraiser.
* `resultchan` - file descriptor referring to the channel of communication to the client requesting the
  appraisal, which is normally used to transfer the result of appraisal to the client.
* `target` - identification of the attester host.
* `target_type` - type of identification stored in `target` (for instance, "host-port" for a host and
  port combination).
* `resource` - the value provided on the command line to the client, who is requesting the measurement of
  some attester, which maps to some Copland phrase to negotiate over.
* `arg_list` - any arguments that may have been provided to the APB
* `argc` - how many arguments are in `arg_list`.

Not all, or even most, of the arguments to `apb_execute` must be used.

An APB may invoke ASPs to collect measurements. The ASPs available to an APB are stored in a GList called
`asps` in the `apb` argument passed into apb_execute (these were the ASPs identified in the `asps` section
in the apb .xml.in file referenced in the previous section). To reference a specific ASP during
execution, the ASP must be found from the list and then invoked using `asp_execute`. This can be done
with the following example code segment:

.. code-block:: c

    asp = find_asp(apb->asps, "ASPNAME");
    if(asp == NULL) {
        return -1;
    }

    ...

    ret_val = asp_execute(asp, ...);

with the specific ASP name and ASP parameters defined as needed by the APB.

### measurement_spec_callbacks

Each APB must implement the measurement_spec_callbacks found in src/measurement_spec/measurement_spec.h.
The expected behavior of these functions is well documented in that file. They serve to provide some
customized control of how the measurement specification is interpreted and used.

Installation without support for compiling alongside Maat
----------------------------------------------------------

This type of installation is faster and easier that the installation described in the next section, but
does not allow your APB to be compiled and installed alongside the rest of Maat. A prerequisite of this
method is that Maat is already installed. Please consult the Maat documentation for more details on the
installation process.

### APB XML

This file should be placed in the directory containing the XML files of the other APBs. By default this
is located at `/usr/share/maat/apbs`, although if you follow the instructions in the Maat documentation
these files will be installed to the `/opt/maat` prefix such that the APB directory will be
`/opt/maat/share/maat/apbs`. This can differ depending on your specific installation procedure.
Regardless, ensure that the file XML has a valid path to the executable you wish Maat to execute if this
APB is selected.

Once the APB XML has been put into the proper location, an attestation manager will be able to load the
APB as part of negotiations and execute the APB if it is selected.

Installation to compile alongside Maat
--------------------------------------

This type of installation will allow your APB to be compiled, installed, and packaged alongside all the
existing APBs in Maat.

### APB source files

The APB source file should be placed in the `src/apbs` directory of the Maat source code tree along with
the APB's .xml.in file.

### Autotools/Makefile Changes

Edit the `configure.ac` file at the root of the Maat source tree to add one of the following lines:

.. code-block:: none

    DEFAULT_APB([...])

or

.. code-block:: none

    EXTRA_APB([...])

where the ellipses are replaced with the name of your APB. If you make your APB a default APB then it
will always be compiled when you compile Maat, while if you make it an extra APB it will only compile
when the flag `--enable-apb-"..."` is passed to the configure script (for more details about building
Maat, please consult Maat documentation), where the ellipses are replaced with the name of your APB.

In addition to this, you also have to modify the `Makefile.am` located in the `src/apbs` directory. You
must add a section like the following:

.. code-block:: none

    if BUILD_..._APB
    apb_PROGRAMS                   += ..._apb
    "..."_apb_SOURCES = ..._apb.c $(APB_COMMON_SOURCES)
    "..."_apb_LDADD   = $(AM_LIBADD)
    endif

where the ellipses are replaced with the name of your APB. If your APB is enabled to be built, the
Makefile will be generated with a section to compile your APB with the source files and the libraries
specified under the SOURCES and LDADD sections, respectively. There are common sources and libraries that
will be used to compile your APB (stored in the variables referenced above), but other such files can be
specified as needed.

### RPM Manifest

If you want to distribute your version of Maat as a series of RPMs, then a reference to the new
APB must be included in the RPM specification for the RPM to package without an error. Modify the
`rpm/maat.spec` file in the root directory of the Maat source tree to include the following line:

.. code-block:: none

    %{_libexecdir}/maat/apbs/..._apb

where the ellipses are replaced with the name of your APB.

If you wish to build an RPM that does not include your APB, and your APB is a default APB (see the
section `Autotools/Makefile Changes`), you must run the configure script with the `--disable-apb-...`
flag, where the ellipses are replaced by the name of your APB, and remove any line referencing the APB in
the RPM spec file. Then, the APB will not be built with the RPM nor will the RPM manifest expect it. Note
that passing the `--disable-apb-...` flag also prevents your APB being built for other situations such as
installation.

An APB must be a default APB in order to be included into the RPM. If you never want to include your APB
as part of the RPM, consider making it an extra APB.

### Documentation

Modify `documentation/source/security_fs_listing.txt` to include a reference to the Maat user permissions
for your APB by extending the table for the APB executable installation directory. Also add a
reference to the permissions for your APB metadata files to the table for the APB metadata directory.
