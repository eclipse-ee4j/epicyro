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

package org.glassfish.epicyro.config.module.configprovider;

import java.util.Map;

import org.glassfish.epicyro.config.delegate.MessagePolicyDelegate;
import org.glassfish.epicyro.config.delegate.ServletMessagePolicyDelegate;
import org.glassfish.epicyro.config.helper.ModulesManager;

import jakarta.security.auth.message.AuthException;
import jakarta.security.auth.message.config.AuthConfigFactory;
import jakarta.security.auth.message.module.ServerAuthModule;

/**
 *
 * @author Ron Monzillo
 */
public class JAASServletAuthConfigProvider extends JAASAuthConfigProvider {

    private static final String HTTP_SERVLET_LAYER = "HttpServlet";

    private static final Class<?>[] moduleTypes = new Class[] { ServerAuthModule.class };

    private static final MessagePolicyDelegate MESSAGE_POLICY_DELEGATE = new ServletMessagePolicyDelegate();

    public JAASServletAuthConfigProvider(Map<String, String> properties, AuthConfigFactory factory) {
        super(properties, factory);
    }

    @Override
    public MessagePolicyDelegate getMessagePolicyDelegate(String appContext) throws AuthException {
        return MESSAGE_POLICY_DELEGATE;
    }

    @Override
    protected Class<?>[] getModuleTypes() {
        return moduleTypes;
    }

    @Override
    protected String getLayer() {
        return HTTP_SERVLET_LAYER;
    }
    
    @Override
    public ModulesManager getModulesManager(String appContext, boolean returnNullContexts) throws AuthException {
        // overrides returnNullContexts to false (as required by Servlet Container Profile)
        return super.getModulesManager(appContext, false);
    }


}
