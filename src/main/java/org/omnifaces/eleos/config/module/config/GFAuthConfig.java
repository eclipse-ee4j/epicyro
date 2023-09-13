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
import static org.omnifaces.eleos.config.helper.ModuleConfigurationManager.createAuthModuleInstance;
import static org.omnifaces.eleos.config.helper.ModuleConfigurationManager.getAuthModuleConfig;
import static org.omnifaces.eleos.config.helper.ModuleConfigurationManager.loadParser;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.config.AuthConfig;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.AuthConfigProvider;

import org.omnifaces.eleos.config.helper.AuthMessagePolicy;
import org.omnifaces.eleos.data.AuthModuleBaseConfig;
import org.omnifaces.eleos.data.AuthModuleInstanceHolder;

public class GFAuthConfig implements AuthConfig {

    protected AuthConfigProvider provider;
    protected String layer;
    protected String appContext;
    protected CallbackHandler handler;
    protected String type;
    protected String moduleId;
    
    protected boolean init;
    protected boolean onePolicy;

    protected AuthConfigFactory factory;

    public GFAuthConfig(AuthConfigProvider provider, String layer, String appContext, CallbackHandler handler, String type) {
        this.provider = provider;
        this.layer = layer;
        this.appContext = appContext;
        this.handler = handler != null ? handler : AuthMessagePolicy.getDefaultCallbackHandler();
        this.type = type;
    }

    @Override
    public String getMessageLayer() {
        return layer;
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
        if (HTTPSERVLET.equals(layer)) {
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
        loadParser(provider, factory, null);
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

        AuthModuleBaseConfig authModuleConfig = getAuthModuleConfig(layer, moduleId, policies[0], policies[1], type);
        if (authModuleConfig == null) {
            return null;
        }

        return createAuthModuleInstance(authModuleConfig, handler, type, properties);
    }

    private void initialize(Map<String, ?> properties) {
        if (!init) {
            if (HTTPSERVLET.equals(layer)) {
                moduleId = (String) properties.get("authModuleId");
                onePolicy = true;
            }

            // HandlerContext need to be explicitly set by caller
            init = true;
        }
    }



}
