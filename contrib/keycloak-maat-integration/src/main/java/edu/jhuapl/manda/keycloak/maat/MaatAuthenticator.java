/*
 * Copyright 2024 United States Government
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
package edu.jhuapl.manda.keycloak.maat;

import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

import java.lang.Process;
import java.lang.String;
import java.lang.Runtime;
import java.lang.InterruptedException;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.IOException;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;

import org.keycloak.common.ClientConnection;

import org.keycloak.models.UserModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.AuthenticatorConfigModel;

import org.keycloak.models.KeycloakSession;

import lombok.extern.jbosslog.JBossLog;

@JBossLog
public class MaatAuthenticator implements Authenticator {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        final KeycloakSession session = context.getSession();
        final ClientConnection conn = context.getConnection();

        final String attesterIPAddress = conn.getRemoteAddr();

        final String appraiserIPAddress = getAppraiserAddress(context);
        final String maatPort = getMaatPort(context);
        final String resource = getResource(context);
        final String client = getClient(context);

        final String command = client + " -l " + appraiserIPAddress + " -a " + maatPort + " -t  " + attesterIPAddress + " -p " + maatPort + " -r " + resource;

        final Runtime runtime = Runtime.getRuntime();
        Process client_run;

        log.infof("Going to authenticate client using the command %s to run", command);

        try {
            client_run = runtime.exec(command);
        } catch (IOException e) {
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
            return;
        }

        try {
            client_run.waitFor();
        } catch (InterruptedException e) {}

        final InputStream result = client_run.getInputStream();

        if (getResult(result)) {
            log.info("Authentication succeeded");
            context.success();
        } else {
            log.warn("Authentication failed");
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
        }
    }

    private String getAppraiserAddress(AuthenticationFlowContext context) {
        final AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        final Map<String, String> config = configModel.getConfig();
        return config.get(MaatAuthenticatorFactory.APPRAISER_IP_CONFIG);
    }

    private String getMaatPort(AuthenticationFlowContext context) {
        final AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        final Map<String, String> config = configModel.getConfig();
        return config.get(MaatAuthenticatorFactory.MAAT_PORT_CONFIG);
    }

    private String getResource(AuthenticationFlowContext context) {
        final AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        final Map<String, String> config = configModel.getConfig();
        return config.get(MaatAuthenticatorFactory.RESOURCE_CONFIG);
    }

    private String getClient(AuthenticationFlowContext context) {
        final AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        final Map<String, String> config = configModel.getConfig();
        return config.get(MaatAuthenticatorFactory.CLIENT_CONFIG);
    }

    private boolean getResult(InputStream appraisalResult) {
        try (final BufferedReader reader = new BufferedReader(new InputStreamReader(appraisalResult))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("PASS")) {
                    return true;
                }
            }
        } catch (IOException e) {}

        return false;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }

}
