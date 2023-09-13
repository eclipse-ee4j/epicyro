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

package org.omnifaces.eleos.config.module.config;

import static org.omnifaces.eleos.config.helper.AuthMessagePolicy.getHttpServletPolicies;
import static org.omnifaces.eleos.config.helper.HttpServletConstants.HTTPSERVLET;
import static org.omnifaces.eleos.config.helper.HttpServletConstants.IS_MANDATORY;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;

import org.omnifaces.eleos.config.helper.AuthMessagePolicy;
import org.omnifaces.eleos.config.helper.ModuleConfigurationManager;
import org.omnifaces.eleos.data.AuthModuleBaseConfig;
import org.omnifaces.eleos.data.AuthModuleInstanceHolder;

import jakarta.security.auth.message.AuthException;
import jakarta.security.auth.message.MessageInfo;
import jakarta.security.auth.message.MessagePolicy;
import jakarta.security.auth.message.config.AuthConfig;
import jakarta.security.auth.message.config.AuthConfigFactory;
import jakarta.security.auth.message.config.AuthConfigProvider;

public class GFAuthConfig implements AuthConfig {

    protected ModuleConfigurationManager moduleConfigurationManager;
    protected AuthConfigProvider authConfigProvider;
    protected String messageLayer;
    protected String appContext;
    protected CallbackHandler handler;
    protected String authModuleType;

    protected String authModuleId;
    protected boolean init;
    protected boolean onePolicy;

    protected AuthConfigFactory authConfigFactory;

    public GFAuthConfig(ModuleConfigurationManager moduleConfigurationManager, AuthConfigProvider authConfigProvider, String messageLayer, String appContext, CallbackHandler handler, String authModuleType) {
        this.moduleConfigurationManager = moduleConfigurationManager;
        this.authConfigProvider = authConfigProvider;
        this.messageLayer = messageLayer;
        this.appContext = appContext;
        this.handler = handler != null ? handler : AuthMessagePolicy.getDefaultCallbackHandler();
        this.authModuleType = authModuleType;
    }

    @Override
    public String getMessageLayer() {
        return messageLayer;
    }

    @Override
    public String getAppContext() {
        return appContext;
    }

    /**
     * Get the authentication context identifier corresponding to the request and response objects encapsulated in
     * messageInfo.
     *
     * See method AuthMessagePolicy. getHttpServletPolicies() for more details on why this method returns the Strings
     * "true" or "false" for AuthContextID.
     *
     * @param messageInfo a contextual Object that encapsulates the client request and server response objects.
     *
     * @return the authentication context identifier corresponding to the encapsulated request and response objects, or
     * null.
     *
     * @throws IllegalArgumentException if the type of the message objects incorporated in messageInfo are not compatible
     * with the message types supported by this authentication context configuration object.
     */
    @Override
    public String getAuthContextID(MessageInfo messageInfo) {
        if (HTTPSERVLET.equals(messageLayer)) {
            return Boolean.valueOf((String) messageInfo.getMap().get(IS_MANDATORY)).toString();
        }

        return null;
    }

    // we should be able to replace the following with a method on packet

    /**
     * Causes a dynamic authentication context configuration object to update the internal state that it uses to process
     * calls to its <code>getAuthContext</code> method.
     *
     */
    @Override
    public void refresh() {
        moduleConfigurationManager.loadParser(authConfigProvider, authConfigFactory, null);
    }

    @Override
    public boolean isProtected() {
        // XXX TBD
        return true;
    }

    CallbackHandler getCallbackHandler() {
        return handler;
    }

    protected AuthModuleInstanceHolder getAuthModuleInstanceHolder(String authContextID, Map<String, Object> properties) throws AuthException {
        if (!init) {
            initialize(properties);
        }

        // For now only HTTP supported. Add support for other layers in the future.
        MessagePolicy[] policies = getHttpServletPolicies(authContextID);

        AuthModuleBaseConfig authModuleConfig = moduleConfigurationManager.getAuthModuleConfig(messageLayer, authModuleId, policies[0], policies[1], authModuleType);
        if (authModuleConfig == null) {
            return null;
        }

        return moduleConfigurationManager.createAuthModuleInstance(authModuleConfig, handler, authModuleType, properties);
    }

    private void initialize(Map<String, ?> properties) {
        if (!init) {
            if (HTTPSERVLET.equals(messageLayer)) {
                authModuleId = (String) properties.get("authModuleId");
                onePolicy = true;
            }

            // HandlerContext need to be explicitly set by caller
            init = true;
        }
    }

}
