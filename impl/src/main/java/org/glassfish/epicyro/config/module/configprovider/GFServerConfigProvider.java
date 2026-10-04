/*
 * Copyright (c) 2024 OmniFish and/or its affiliates. All rights reserved.
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

package org.glassfish.epicyro.config.module.configprovider;

import jakarta.security.auth.message.AuthException;
import jakarta.security.auth.message.config.AuthConfigFactory;
import jakarta.security.auth.message.config.AuthConfigProvider;
import jakarta.security.auth.message.config.ClientAuthConfig;
import jakarta.security.auth.message.config.ServerAuthConfig;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import javax.security.auth.callback.CallbackHandler;

import org.glassfish.epicyro.config.factory.ConfigParser;
import org.glassfish.epicyro.config.helper.ModuleConfigurationManager;
import org.glassfish.epicyro.config.helper.ObjectUtils;
import org.glassfish.epicyro.config.module.config.GFClientAuthConfig;
import org.glassfish.epicyro.config.module.config.GFServerAuthConfig;

/**
 * This class implements the interface AuthConfigProvider.
 *
 * @author Shing Wai Chan
 * @author Ronald Monzillo
 */
public class GFServerConfigProvider implements AuthConfigProvider {

    protected Map<String, Object> properties;
    protected ModuleConfigurationManager moduleConfigurationManager;
    protected AuthConfigFactory authConfigFactory;

    public GFServerConfigProvider(ConfigParser configParser, AuthConfigFactory authConfigFactory) {
        this(new HashMap<>(), configParser, authConfigFactory);
    }

    public GFServerConfigProvider(Map<String, Object> properties, AuthConfigFactory authConfigFactory) {
        this(properties, newConfigParser(), authConfigFactory);
    }

    public GFServerConfigProvider(Map<String, Object> properties, ConfigParser configParser, AuthConfigFactory authConfigFactory) {
        this.properties = properties;
        this.authConfigFactory = authConfigFactory;
        this.moduleConfigurationManager = new ModuleConfigurationManager(configParser, authConfigFactory, this);
    }

    public GFServerConfigProvider(ModuleConfigurationManager moduleConfigurationManager, AuthConfigFactory authConfigFactory) {
        this.moduleConfigurationManager = moduleConfigurationManager;
        this.authConfigFactory = authConfigFactory;
    }

    @Override
    public ClientAuthConfig getClientAuthConfig(String messageLayer, String appContextId, CallbackHandler handler) throws AuthException {
        return new GFClientAuthConfig(properties, moduleConfigurationManager, this, messageLayer, appContextId, handler);
    }

    @Override
    public ServerAuthConfig getServerAuthConfig(String messageLayer, String appContextId, CallbackHandler handler) throws AuthException {
        return new GFServerAuthConfig(properties, moduleConfigurationManager, this, messageLayer, appContextId, handler);
    }

    @Override
    public void refresh() {
        moduleConfigurationManager.loadParser(this, authConfigFactory, null);
    }

    private static ConfigParser newConfigParser() {
        String configParser = System.getProperty("config.parser");
        if (configParser == null) {
            return null;
        }

        return ObjectUtils.createObject(configParser);
    }

}
