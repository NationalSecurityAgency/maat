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

Build Maat Docker Image 
=======================

Starting within the `maat/contrib/docker/` directory, pull the Dockerfile 'above' the Maat 
directory in the file hierarchy (this file needs to be able to 'see' the maat codebase and 
subsequently build it):

```
$ cd ../../..
$ ln -s ./maat/contrib/docker/Dockerfile . 
```

Build the Maat Docker image:

`$ docker build -t "maat:v0" .`

Once the build is complete, running the command `docker image list` should list the Maat
Docker image (as shown below). This image will serve as the starting point for all 
examples that follow. 

```
$ docker image list
REPOSITORY                       TAG                IMAGE ID       CREATED              SIZE
maat                             v0                 b5a495014157   About a minute ago   557MB
```

Basic Maat Attestation / Appraisal Example
===========================================

Maat can act as an appraiser or an attester, or both, depending on the current scenario 
and administrative settings. 

To run the most basic Maat Attestation / Appraisal example, use the 
`docker-compose-basic.yml` file to set up two Maat containers. In this example the 
`maat-appraiser` container will act as the Appraiser, and the `maat-attester` container 
will act as the Attester.

```
$ cd maat/contrib/docker/
$ docker-compose -f docker-compose-basic.yml up
Creating network "docker_default" with the default driver
Creating maat-appraiser ... done
Creating maat-attester  ... done
Attaching to maat-appraiser, maat-attester
maat-appraiser | Attestation Manager initializing
maat-attester | Attestation Manager initializing
...
maat-attester | Attestation Manager is ready to start accepting requests
maat-appraiser | (   1) [load_measurement:123]	: Registered mspec: memory mapping  measurement specification
maat-attester | (   1) [load_selector_co:594]	: Warning: no collections in xml schema
maat-attester | (   1) [setup_dispatch_l:854]	: Entering wait_on_connection loop on 1 listen interfaces!
maat-attester | (   1) [wait_for_connect:651]	: setting fd 4
maat-appraiser | (   1) [load_selector_co:594]	: Warning: no collections in xml schema
maat-appraiser | (   1) [setup_dispatch_l:854]	: Entering wait_on_connection loop on 1 listen interfaces!
maat-appraiser | (   1) [wait_for_connect:651]	: setting fd 4
maat-appraiser | Attestation Manager is ready to start accepting requests
```

> You can also add the `-d` flag to the `docker-compose` command to instruct Docker to run 
> the containers in 'detached' mode, i.e., they will run in the background. 


After running the `docker-compose` command above, you will have two Docker containers
running on your system, `maat-appraiser` and `maat-attester`. To confirm this, use the 
command `docker ps` to see the containers currently running on your system. 

```
$ docker ps
CONTAINER ID   IMAGE     COMMAND                  CREATED         STATUS         PORTS                    NAMES
5645077764c6   maat:v0   "/bin/bash -c 'LIBMA…"   4 minutes ago   Up 2 minutes   0.0.0.0:2342->2342/tcp   maat-appraiser
21244611b98d   maat:v0   "/bin/bash -c 'LIBMA…"   4 minutes ago   Up 2 minutes   0.0.0.0:2343->2343/tcp   maat-attester
```

Take a look at the `docker-compose-basic.yml` script that was used to bring up the 
`maat-appraiser` and `maat-attester` containers. The only difference between the commands 
used to run each container's Maat Attestation Manager (AM) is the port the AM is 
instructed to listen on (`2342` and `2343`, respectively). Each AM is given the same 
configuration files and is able to act as an appraiser and/or an attester. 

To run an example attestation request and receive the response, use the CONTAINER ID from 
the `docker ps` command to get a bash terminal into the `maat-appraiser` container. 

```
$ docker exec -it 5645077764c6 /bin/bash
root@maat-appraiser:/# 
```

Use the `test_client` executable to ask the `maat-appraiser` to negotiate and appraise a 
measurement of the `maat-attester`'s `packages` resource. This `test_client` executable
simulates the initiation of this request scenario from a third-party resource, such as a 
NAC component reaching out to its local AM to verify the integrity of a remote attester 
machine before granting access.

```
root@maat-appraiser:/# /opt/maat/bin/test_client -l maat-appraiser -a 2342 -t maat-attester -p 2343 -r packages
measuring target: maat-attester : 172.18.0.3
connecting to appraiser: 172.18.0.2 : 2342
DEBUG!!!! Target type matches host-port
sending request: <?xml version="1.0"?>
<contract version="2.0" type="request"><target type="host-port">172.18.0.3<host>172.18.0.3</host><port>2343</port></target><resource>packages</resource></contract>

Result from Appraiser: <?xml version="1.0"?>
<contract version="2.0" type="response"><target type="host-port">127.0.0.1</target><resource>packages</resource><result>PASS</result><data>
(...)
</data><AttestationCredential fingerprint="B9:17:2D:8B:58:FD:9E:6C:62:0A:8A:5C:F6:8A:78:00:A5:1B:90:CF">-----BEGIN CERTIFICATE-----
(...)
-----END CERTIFICATE-----
</AttestationCredential><signature><signedinfo><canonicalizationmethod algorithm="XML C14N 1.0"/><signaturemethod algorithm="RSA"/><digestmethod algorithm="SHA-1"/></signedinfo><signaturevalue>mXCr+gy82gqpmKqYZBAIxjqrq8zV0ua8/UU04BpysC3NdT6docwDjFaNnvXbxm4+PgXsh9z0pFLnoRQAK/zPQjCv75hdxTX8uVqWtS28zX4LCeKBwqsEIx/SSlIbzvW5Nd+oDBheh4xO8AA8XSqlFpDlcdVvTtFAoAr4pYmfiH69pSnOa6IUlbwB8GxbSeElXUWEeEWbeI/OKz59pqhoUePuwyZxzWoAKD09IIB7YivYIBdsjUBeInrVwmwd8Z5NnC4aifj/YQpQCJQpwIluI7NGKZdeLN3mgJEywOK76e6yEvYvq0exis/dHEpv+fgOsZhB9yNpzvRsfe0mBWhg88kQbpvnn48HawT/AB1RXMUGj+Q51Qo6c2ZNuda8XB/KnVWahMzMRf4EK4rkPUwCGDSvxorlrh+5b7w4I5Bb2HJ0CSj5ZPZydDK/fS1q51PJiad5V/Maxf8q9BcIdLLX4TWwhOOkaRNPJprnap/k0U/tsY2BZdquadEGs3lPYpkx</signaturevalue><keyinfo>B9:17:2D:8B:58:FD:9E:6C:62:0A:8A:5C:F6:8A:78:00:A5:1B:90:CF</keyinfo></signature></contract>
```

The `packages` measurement executed above requests a software inventory from the 
`maat-attester` container. The `maat-appraiser` container then appraises the measurement
against a local blacklist file. The result of the measurement is then returned to the
`test_client` instance, and the overall result can be seen in the result tags 
(`<result>PASS</result>` above). 

To further demonstrate the point that a Maat AM can act as either/both the attester or 
appraiser, try switching the command line arguments from the `test_client`. In the example 
below, the `test_client` sends a request for the `maat-attester` container to measure and 
appraise the `packages` measurement from the `maat-appraiser` container. I.e., the  
`maat-appraiser` container acts as the _Attester_ and the `maat-attester` container acts 
as the _Appraiser_. 

```
root@maat-appraiser:/# /opt/maat/bin/test_client -l maat-attester -a 2343 -t maat-appraiser -p 2342 -r packages
measuring target: maat-appraiser : 172.18.0.3
connecting to appraiser: 172.18.0.2 : 2343
DEBUG!!!! Target type matches host-port
sending request: <?xml version="1.0"?>
<contract version="2.0" type="request"><target type="host-port">172.18.0.3<host>172.18.0.3</host><port>2342</port></target><resource>packages</resource></contract>

Result from Appraiser: <?xml version="1.0"?>
<contract version="2.0" type="response"><target type="host-port">172.18.0.3</target><resource>packages</resource><result>PASS</result><data>
(...)
</data><AttestationCredential fingerprint="A5:2C:D0:4E:1A:75:1F:7D:60:9F:2B:A6:D1:7D:EA:53:BD:42:B7:FD">-----BEGIN CERTIFICATE-----
(...)
-----END CERTIFICATE-----
</AttestationCredential><signature><signedinfo><canonicalizationmethod algorithm="XML C14N 1.0"/><signaturemethod algorithm="RSA"/><digestmethod algorithm="SHA-1"/></signedinfo><signaturevalue>qYMTe/SH0jxscUtZJBRSO+W4vD/QEYMJ57+2jwRMmoOBYp0i2vgK6Tg2MXhohj6PYgCHeaqG+PdItHIMqkNcqPnUNcW/7oiPM4NROR2LpZWFNkGdF/r4TDnzbQ2sUnjDTabyAKhW6A0QZAOVnbCuN+47IcFc8qLLIb9rWqbgRAjOZFUgsDylfrF+PmnXbTG7+UJmlyQKu8jVx46K0F42Xp5Eqi8yivrzNFiNE735xTfwgsw0962ZPcyXr+7HT3Se8KN7nmsCcO6NvelNSX5w7+l9oEUUUeeF6lgugNsUPYT96BytA93qtZXoR4L1BdQH3rTPnOZ/naqidkW0rQQEV0ir6aos0eA1DUUMvacBY5rIsXtzXHFsBhAzIqYEhORZe/QxFPymr0r08h35NBH70TlN/7iWMLYLJWmPO9duI9GWp7g12z77i2zJYdeMmDrcoSQ2M206Jrkd3u1IkZB1BzVE6MGNHWuXf9iPS4JRImQ8BRCBdbvhaLehd7rLUTR6</signaturevalue><keyinfo>A5:2C:D0:4E:1A:75:1F:7D:60:9F:2B:A6:D1:7D:EA:53:BD:42:B7:FD</keyinfo></signature></contract>

```

And in the example below, the `maat-appraiser` container acts as both the Appraiser and 
the Attester, taking and evaluating a measurement of itself. 

```
root@maat-appraiser:/# /opt/maat/bin/test_client -l maat-appraiser -a 2342 -t maat-appraiser -p 2342 -r packages
measuring target: maat-appraiser : 172.18.0.3
connecting to appraiser: 172.18.0.3 : 2342
DEBUG!!!! Target type matches host-port
sending request: <?xml version="1.0"?>
<contract version="2.0" type="request"><target type="host-port">172.18.0.3<host>172.18.0.3</host><port>2342</port></target><resource>packages</resource></contract>

Result from Appraiser: <?xml version="1.0"?>
<contract version="2.0" type="response"><target type="host-port">172.18.0.3</target><resource>packages</resource><result>PASS</result><data>
(...)
</data><AttestationCredential fingerprint="A5:2C:D0:4E:1A:75:1F:7D:60:9F:2B:A6:D1:7D:EA:53:BD:42:B7:FD">-----BEGIN CERTIFICATE-----
(...)
-----END CERTIFICATE-----
</AttestationCredential><signature><signedinfo><canonicalizationmethod algorithm="XML C14N 1.0"/><signaturemethod algorithm="RSA"/><digestmethod algorithm="SHA-1"/></signedinfo><signaturevalue>qYMTe/SH0jxscUtZJBRSO+W4vD/QEYMJ57+2jwRMmoOBYp0i2vgK6Tg2MXhohj6PYgCHeaqG+PdItHIMqkNcqPnUNcW/7oiPM4NROR2LpZWFNkGdF/r4TDnzbQ2sUnjDTabyAKhW6A0QZAOVnbCuN+47IcFc8qLLIb9rWqbgRAjOZFUgsDylfrF+PmnXbTG7+UJmlyQKu8jVx46K0F42Xp5Eqi8yivrzNFiNE735xTfwgsw0962ZPcyXr+7HT3Se8KN7nmsCcO6NvelNSX5w7+l9oEUUUeeF6lgugNsUPYT96BytA93qtZXoR4L1BdQH3rTPnOZ/naqidkW0rQQEV0ir6aos0eA1DUUMvacBY5rIsXtzXHFsBhAzIqYEhORZe/QxFPymr0r08h35NBH70TlN/7iWMLYLJWmPO9duI9GWp7g12z77i2zJYdeMmDrcoSQ2M206Jrkd3u1IkZB1BzVE6MGNHWuXf9iPS4JRImQ8BRCBdbvhaLehd7rLUTR6</signaturevalue><keyinfo>A5:2C:D0:4E:1A:75:1F:7D:60:9F:2B:A6:D1:7D:EA:53:BD:42:B7:FD</keyinfo></signature></contract>
```

Negotiation Example
====================

Each Maat AM is configured with a selection policy that instructs the AM how to handle
different incoming measurement requests. In this example, we demonstrate an AM acting as 
an Appraiser and using its selection policy to choose a different measurement for other 
AMs depending on the identity of the Attesting AM. The example contained here is rather
contrived, but could be extended to make measurement decisions based on security 
associations, etc.

Stop any Maat Docker instances running on your system, then in the `maat/contrib/docker/`
directory, use the following command to bring up the three containers for this example.

```
$ cd maat/contrib/docker/
$ docker-compose -f docker-compose-negotiation.yml up
Starting maat-appraiser   ... done
Creating known-attester   ... done
Creating unknown-attester ... done
Attaching to maat-appraiser, known-attester, unknown-attester
maat-appraiser      | Attestation Manager initializing
known-attester      | Attestation Manager initializing
maat-appraiser      | (   1) [load_selector_co:312]	: Warning: selector in configuration file was overridden
maat-appraiser      | (   1) [setup_interfaces:716]	: Listening on INET interface 0.0.0.0:2342
unknown-attester    | Attestation Manager initializing
(...)
maat-appraiser      | Attestation Manager is ready to start accepting requests
unknown-attester    | (   1) [load_measurement:123]	: Registered mspec: test measurement specification
unknown-attester    | (   1) [load_measurement:123]	: Registered mspec: hashfiles mspec
known-attester      | (   1) [load_measurement:123]	: Registered mspec: memory mapping  measurement specification
unknown-attester    | (   1) [load_measurement:123]	: Registered mspec: proc open files  measurement specification
known-attester      | Attestation Manager is ready to start accepting requests
unknown-attester    | (   1) [load_measurement:123]	: Registered mspec: ls proc mspec
known-attester      | (   1) [load_selector_co:594]	: Warning: no collections in xml schema
known-attester      | (   1) [setup_dispatch_l:854]	: Entering wait_on_connection loop on 1 listen interfaces!
known-attester      | (   1) [wait_for_connect:651]	: setting fd 4
unknown-attester    | (   1) [load_measurement:123]	: Registered mspec: memory mapping  measurement specification
unknown-attester    | Attestation Manager is ready to start accepting requests
unknown-attester    | (   1) [load_selector_co:594]	: Warning: no collections in xml schema
unknown-attester    | (   1) [setup_dispatch_l:854]	: Entering wait_on_connection loop on 1 listen interfaces!
unknown-attester    | (   1) [wait_for_connect:651]	: setting fd 4
```

The `docker ps` command should now show three Maat containers running on your system: 

```
$ docker ps
CONTAINER ID   IMAGE     COMMAND                  CREATED          STATUS          PORTS                    NAMES
77139ad8b994   maat:v0   "/bin/bash -c 'LIBMA…"   15 seconds ago   Up 14 seconds   0.0.0.0:2344->2344/tcp   unknown-attester
606bafe926d7   maat:v0   "/bin/bash -c 'LIBMA…"   15 seconds ago   Up 14 seconds   0.0.0.0:2343->2343/tcp   known-attester
5645077764c6   maat:v0   "/bin/bash -c 'LIBMA…"   20 hours ago     Up 14 seconds   0.0.0.0:2342->2342/tcp   maat-appraiser
```

Use the `CONTANINER ID` output by `docker ps` to set up a shell into the `maat-appraiser`
container. 

```
$ docker exec -it 5645077764c6 /bin/bash
root@maat-appraiser:/# 
```

Request a measurement of the `known-attester` container; the `maat-appraiser` will 
negotiate for and appraise the package inventory measurement, as performed in the 
previous example.

```
root@maat-appraiser:/# /opt/maat/bin/test_client -l maat-appraiser -a 2342 -t known-attester -p 2343
measuring target: known-attester : 172.18.0.3
connecting to appraiser: 172.18.0.4 : 2342
DEBUG!!!! Target type matches host-port
sending request: <?xml version="1.0"?>
<contract version="2.0" type="request"><target type="host-port">172.18.0.3<host>172.18.0.3</host><port>2343</port></target><resource>debug resource</resource></contract>

Result from Appraiser: <?xml version="1.0"?>
<contract version="2.0" type="response"><target type="host-port">172.18.0.3</target><resource>debug resource</resource><result>PASS</result><data>
(...)
</contract>
```

On the output from the Docker containers, you should see the size of the measurement, 
containing hundreds of 'package' type nodes, e.g., 

```
known-attester      | ( 490) [graph_print_stat:38]	: Gathering Graph statistics...
known-attester      | ( 490) [graph_print_stat:103]	: Evidence Graph Statistics:
known-attester      | ( 490) [graph_print_stat:104]	: 	Num Nodes: 239
known-attester      | ( 490) [graph_print_stat:107]	: 		238 nodes of type package
known-attester      | ( 490) [graph_print_stat:110]	: 	Num Edges: 238
known-attester      | ( 490) [graph_print_stat:113]	: 		238 edges with label pkginv.packages
known-attester      | ( 970) [serialize_measur:155]	: Serializing Measurement Graph
known-attester      | ( 490) [     apb_execute:582]	: Total time: 2 seconds
maat-appraiser      | ( 514) [xpath_delete_nod:477]	: Deleting node: signature
maat-appraiser      | ( 514) [graph_print_stat:38]	: Gathering Graph statistics...
maat-appraiser      | ( 514) [graph_print_stat:103]	: Evidence Graph Statistics:
maat-appraiser      | ( 514) [graph_print_stat:104]	: 	Num Nodes: 239
maat-appraiser      | ( 514) [graph_print_stat:107]	: 		238 nodes of type package
maat-appraiser      | ( 514) [graph_print_stat:110]	: 	Num Edges: 238
maat-appraiser      | ( 514) [graph_print_stat:113]	: 		238 edges with label pkginv.packages
maat-appraiser      | ( 514) [   appraise_node:509]	: Warning: Failed to find an appraiser ASP for node of type 00000cac
maat-appraiser      | ( 514) [handle_satisfier:180]	: Appraisal succeeded
```

Now, request a measurement of the `unknown-attester` container. The `maat-appraiser` will
negotiate for and appraise the _full_ userspace measurement. As this container is 
'unknown' to the appraiser, the appraiser requires a more complete measurement in order 
to gain confidence in the attester's integrity.

```
root@maat-appraiser:/# /opt/maat/bin/test_client -l maat-appraiser -a 2342 -t unknown-attester -p 2344
measuring target: unknown-attester : 172.18.0.2
connecting to appraiser: 172.18.0.4 : 2342
DEBUG!!!! Target type matches host-port
sending request: <?xml version="1.0"?>
<contract version="2.0" type="request"><target type="host-port">172.18.0.2<host>172.18.0.2</host><port>2344</port></target><resource>debug resource</resource></contract>

Result from Appraiser: <?xml version="1.0"?>
<contract version="2.0" type="response"><target type="host-port">172.18.0.2</target><resource>debug resource</resource><result>PASS</result><data>
(...)
</contract>
```

You can see evidence of this larger measurement in the output from the Docker containers; 
they will now contain nodes for file measurements, etc.:

```
unknown-attester    | ( 523) [graph_print_stat:38]	: Gathering Graph statistics...
unknown-attester    | ( 523) [graph_print_stat:103]	: Evidence Graph Statistics:
unknown-attester    | ( 523) [graph_print_stat:104]	: 	Num Nodes: 276
unknown-attester    | ( 523) [graph_print_stat:107]	: 		14 nodes of type simple_file
unknown-attester    | ( 523) [graph_print_stat:107]	: 		238 nodes of type package
unknown-attester    | ( 523) [graph_print_stat:107]	: 		22 nodes of type file
unknown-attester    | ( 523) [graph_print_stat:110]	: 	Num Edges: 262
unknown-attester    | ( 523) [graph_print_stat:113]	: 		14 edges with label path_list.paths
unknown-attester    | ( 523) [graph_print_stat:113]	: 		238 edges with label pkginv.packages
unknown-attester    | ( 523) [graph_print_stat:113]	: 		8 edges with label path_list.files
unknown-attester    | ( 523) [graph_print_stat:113]	: 		2 edges with label path_list.directories
```








