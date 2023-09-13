/*
 * Copyright (c) 1997, 2018 Oracle and/or its affiliates. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0, which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * This Source Code may also be made available under the following Secondary
 * Licenses when the conditions for such availability set forth in the
 * Eclipse Public License v. 2.0 are satisfied: GNU General Public License,
 * version 2 with the GNU Classpath Exception, which is available at
 * https://www.gnu.org/software/classpath/license.html.
 *
 * SPDX-License-Identifier: EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0
 */

package org.omnifaces.eleos.config.module.configprovider;

import java.util.Locale;
import java.util.Map;

import jakarta.security.auth.message.AuthException;
import jakarta.security.auth.message.config.AuthConfigFactory;
import jakarta.security.auth.message.config.AuthConfigFactory.RegistrationContext;

import org.omnifaces.eleos.config.helper.JAASModulesManager;
import org.omnifaces.eleos.config.helper.ModulesManager;
import org.omnifaces.eleos.config.jaas.ExtendedConfigFile;

/**
 *
 * @author Ron Monzillo
 */
public abstract class JAASAuthConfigProvider extends BaseAuthConfigProvider {

    private static final String CONFIG_FILE_NAME_KEY = "config.file.name";
    private static final String DEFAULT_JAAS_APP_NAME = "other";
    private static final String ALL_APPS = "*";

    private ExtendedConfigFile jaasConfigFile;

    private Map<String, ?> properties;
    private AuthConfigFactory factory;

    public JAASAuthConfigProvider(Map<String, ?> properties, AuthConfigFactory factory) {
        this.properties = properties;
        this.factory = factory;
        this.jaasConfigFile = ExtendedConfigFile.fromFileName(getProperty(CONFIG_FILE_NAME_KEY, null));

        selfRegister();
    }

    @Override
    public Map<String, ?> getProperties() {
        return properties;
    }

    @Override
    public AuthConfigFactory getFactory() {
        return factory;
    }

    @Override
    public AuthConfigFactory.RegistrationContext[] getSelfRegistrationContexts() {
        String[] appContexts = jaasConfigFile.getAppNames(getModuleTypes());

        RegistrationContext[] selfRegistrationContexts = new RegistrationContext[appContexts.length];
        for (int i = 0; i < appContexts.length; i++) {
            selfRegistrationContexts[i] = getRegistrationContext(appContexts[i]);
        }

        return selfRegistrationContexts;
    }

    @Override
    public ModulesManager getModulesManager(String appContext, boolean returnNullContexts) throws AuthException {
        return new JAASModulesManager(getLogManager(), returnNullContexts, jaasConfigFile, properties, appContext);
    }

    @Override
    public void refresh() {
        jaasConfigFile.refresh();
        super.refresh();
    }

    private RegistrationContext getRegistrationContext(String id) {
        String layer = getLayer();
        String appContext;

        if (id.toLowerCase(Locale.getDefault()).equals(DEFAULT_JAAS_APP_NAME)) {
            appContext = ALL_APPS;
        } else {
            appContext = id;
        }

        return new RegistrationContext() {

            String description = "JAAS AuthConfig: " + appContext;

            @Override
            public String getMessageLayer() {
                return layer;
            }

            @Override
            public String getAppContext() {
                return appContext;
            }

            @Override
            public String getDescription() {
                return description;
            }

            @Override
            public boolean isPersistent() {
                return false;
            }
        };
    }

}
