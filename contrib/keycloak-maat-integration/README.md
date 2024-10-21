COPYRIGHT
=========

Copyright 2024 United States Government

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Keycloak Maat Integration
=========================

Keycloak is an open source solution for providing identity and access management services [1]. Keycloak provides
system administrators with a series of pluggable modules that each define a specific method of authenticating a
client. System administrators can combine these modules in novel ways to create authorization worklows that best fit
their needs. These workflows can be applied to determine if a client has authorization to access a service.

This repository contains a module that allows Maat measurement and appraisal activities to be included within
Keycloak authentication flows. This module allows the Keycloak server to request the authenticating client,
acting as a Maat attester, submit a specific measurement to a trusted appraiser, who will provide the appraisal
result to the Keycloak server, in order to determine how the authentication flow should proceed. This would allow the
Keycloak server to determine if a client's operating environment is in an expected state before granting them
access to a potentially sensitive service.

Installation
============

This plugin is designed to work with Keycloak 22.0.1, which is available on the Keycloak website [2]. For more
information about installing Keycloak, please consult the relevant documentation [3]. It is best to download the Keycloak
Server download, available as a .zip or .tar.gz archive, for ease of plugin installation relative to the container image.

To build the JAR file that will be used by Keycloak, run the following command:

	mvn package

The JAR file will be built and placed into the target directory which has been created by the build process.
This JAR file must be placed within the providers/ directory contained in the Keycloak distribution in order
to have it be used by Keycloak on startup.

The Maat integration with Keycloak may require an increase to the length of time for which an authenticaticator
can run because some of Maat's measurements are particurally thorough and require more time to execute. Therefore,
depending on the measurements that are expected to be appraised, we will need to make a minor change to the
configuration of the Keycloak server. There are multiple ways to supply the needed configuration. On a temporary
basis, the configuration could be provided to Keycloak via Java command line options. Append the following to the
JAVA_OPTS_APPEND environment variable:

	-Dquarkus.transaction-manager.default-transaction-timeout=3600

which will set the timeout for the authenticator to 3600 seconds.

If you have a large number of configuration settings for your Keycloak server, you can provide a configuration file
on initialization. An example of such a file, which includes an analogue of the configuration option given above, is
provided in the conf/ directory of this repository. To use the config file, copy it into the conf/ directory of your
Keycloak distribution. Then, when starting Keycloak, use the following command line option to have the Keycloak
server use the configuration file:

	--config-file=conf/quarkus.properties

Usage
=====

After the Maat module has been installed and is in use by Keycloak, the Maat authenticator can be used as a
step in any authentication flow. In order to use the Maat autheticator, you must either identify an existing
authentication flow to introduce the Maat authenticator into as a new step to or create a new flow which will
include the Maat authenticator as a step.

When the Maat authenticator is added to a flow, it can be configured with the following options:

1. The Appraiser IP Address - The IP address of the trusted appraiser host
2. The Maat Port - The port that both the trusted appraising and attesting Maat clients are listening on
3. The Resource - The Maat resource of which the attester will be providing a measurement
4. The Requester Client Binary - The filepath on the Keycloak binary that will be sending the inital measurement request (the standard installation location is /opt/maat/bin/test_client)

The operation of the module assumes several things about the operating environment:

1. The authenticating client must have a Maat instance on their platform listening on the designated port
2. There is a trusted appraising Maat instance running on a platform assigned the Appraiser IP address and listening on the designated Maat port
3. The appraiser and attester Maat instances are configured such that they can both successfully negotiate a measurement representing the designated resource and take or appraise the representative measurement, as appropriate
4. The measurement requester triggering the measurement process is installed onto the Keycloak server at the specified filepath

For more information about using Keycloak, please consult the relevant Keycloak documentation [3].

Cleaning
========

To clean any build files, use the following command:

	mvn clean

[1] https://www.keycloak.org/
[2] https://www.keycloak.org/archive/downloads-22.0.1.html
[3] https://www.keycloak.org/archive/documentation-22.0.html
