/*
 * Copyright (c) 2019 OmniFaces. All rights reserved.
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

package org.glassfish.epicyro.services;

import static org.glassfish.epicyro.config.helper.HttpServletConstants.HTTPSERVLET;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;

import org.glassfish.epicyro.config.factory.ConfigParser;
import org.glassfish.epicyro.config.factory.DefaultConfigParser;
import org.glassfish.epicyro.config.helper.AuthMessagePolicy;
import org.glassfish.epicyro.config.module.configprovider.GFServerConfigProvider;
import org.glassfish.epicyro.config.servlet.sam.BasicServerAuthModule;
import org.glassfish.epicyro.config.servlet.sam.FormServerAuthModule;

public class DefaultAuthenticationService extends BaseAuthenticationService {

    public DefaultAuthenticationService(String appContextId, Map<String, Object> properties, ConfigParser parser, CallbackHandler callbackHandler) {
        ConfigParser configParser = parser;

        if (properties.containsKey("authMethod")) {
            if ("basic".equalsIgnoreCase((String) properties.get("authMethod"))) {

                // Defines the modules that we have available. Here it's only a single fixed module.
                DefaultConfigParser newParser = new DefaultConfigParser();
                newParser.withAuthModuleClass(BasicServerAuthModule.class)
                         .getOptions()
                         .put("realmName", properties.get("realmName"));

                // Indicates the module we want to use
                properties.put("authModuleId", BasicServerAuthModule.class.getSimpleName());

                configParser = newParser;
            } else if ("form".equalsIgnoreCase((String) properties.get("authMethod"))) {

                // Defines the modules that we have available. Here it's only a single fixed module.
                DefaultConfigParser newParser = new DefaultConfigParser();
                Map<String, Object> options = newParser.withAuthModuleClass(FormServerAuthModule.class)
                         .getOptions();

                options.put("formLoginPage", properties.get("formLoginPage"));
                options.put("formErrorPage", properties.get("formErrorPage"));


                // Indicates the module we want to use
                properties.put("authModuleId", FormServerAuthModule.class.getSimpleName());

                configParser = newParser;
            }
        }

        init(HTTPSERVLET, appContextId, properties, callbackHandler, null);

        if (properties.containsKey("authModuleId") && !hasExactMatchAuthProvider()) {
            setRegistrationId(
                authConfigFactory.registerConfigProvider(
                    new GFServerConfigProvider(properties, configParser, authConfigFactory),
                    HTTPSERVLET, appContextId,
                    "Eleos provider: " + HTTPSERVLET + ":" + appContextId));
        }

    }

    @Override
    public CallbackHandler getCallbackHandler() {
        return AuthMessagePolicy.getDefaultCallbackHandler();
    }

}
