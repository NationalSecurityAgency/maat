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

import java.util.ArrayList;
import java.util.List;

import lombok.extern.jbosslog.JBossLog;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

@JBossLog
public class MaatAuthenticatorFactory implements AuthenticatorFactory {

    public static final String ID = "maat-authenticator";
    private static final String DISPLAY_TYPE = "Maat Authenticator";
    private static final String HELP_TEXT = "Uses a Maat interaction to appraise a host attempting to be authenticated";

    private static final Authenticator AUTHENTICATOR_INSTANCE = new MaatAuthenticator();

    public static final String APPRAISER_IP_CONFIG = "appraiser_ip";
    private static final String APPRAISER_IP_LABEL = "IP address of the Maat appraiser host";

    public static final String MAAT_PORT_CONFIG = "maat_port";
    private static final String MAAT_PORT_LABEL = "Standard port for Maat service";

    public static final String RESOURCE_CONFIG = "resource";
    private static final String RESOURCE_LABEL = "Maat resource representing what measurement will be taken and appraised";
    private static final String RESOURCE_HELP_TEXT = "Ensure that the resource is represented in both the attester and appraiser hosts' selection policies";

    public static final String CLIENT_CONFIG = "client_exe";
    private static final String CLIENT_LABEL = "Requester executable that will request the appraisal of an attester";

    private static String REF_CAT = "Attestation";

    private static List<ProviderConfigProperty> PROPERTIES = new ArrayList<>();

    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
        AuthenticationExecutionModel.Requirement.REQUIRED,
        AuthenticationExecutionModel.Requirement.ALTERNATIVE,
        AuthenticationExecutionModel.Requirement.DISABLED
    };

    static {
        ProviderConfigProperty appraiserIp = new ProviderConfigProperty();
        ProviderConfigProperty maatPort = new ProviderConfigProperty();
        ProviderConfigProperty resource = new ProviderConfigProperty();
        ProviderConfigProperty client = new ProviderConfigProperty();
        ArrayList<ProviderConfigProperty> props = new ArrayList<>();

        appraiserIp.setType(ProviderConfigProperty.STRING_TYPE);
        appraiserIp.setName(APPRAISER_IP_CONFIG);
        appraiserIp.setLabel(APPRAISER_IP_LABEL);

        maatPort.setType(ProviderConfigProperty.STRING_TYPE);
        maatPort.setName(MAAT_PORT_CONFIG);
        maatPort.setLabel(MAAT_PORT_LABEL);

        resource.setType(ProviderConfigProperty.STRING_TYPE);
        resource.setName(RESOURCE_CONFIG);
        resource.setLabel(RESOURCE_LABEL);
        resource.setHelpText(RESOURCE_HELP_TEXT);

        client.setType(ProviderConfigProperty.STRING_TYPE);
        client.setName(CLIENT_CONFIG);
        client.setLabel(CLIENT_LABEL);

        PROPERTIES.add(appraiserIp);
        PROPERTIES.add(maatPort);
        PROPERTIES.add(resource);
        PROPERTIES.add(client);
    }

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return AUTHENTICATOR_INSTANCE;
    }

    @Override
    public String getDisplayType() {
        return DISPLAY_TYPE;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    @Override
    public String getHelpText() {
        return HELP_TEXT;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return PROPERTIES;
    }

    @Override
    public String getReferenceCategory() {
        return REF_CAT;
    }

    @Override
    public void init(Config.Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return ID;
    }
}
