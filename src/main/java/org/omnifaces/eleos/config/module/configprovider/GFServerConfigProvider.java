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

import java.util.Map;
import java.util.logging.Logger;

import javax.security.auth.callback.CallbackHandler;
//jsr 196 interface types
import javax.security.auth.message.AuthException;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.AuthConfigProvider;
import javax.security.auth.message.config.ClientAuthConfig;
import javax.security.auth.message.config.ServerAuthConfig;

import org.omnifaces.eleos.config.helper.ModuleConfigurationManager;
import org.omnifaces.eleos.config.module.config.GFClientAuthConfig;
import org.omnifaces.eleos.config.module.config.GFServerAuthConfig;

/**
 * This class implements the interface AuthConfigProvider.
 *
 * @author Shing Wai Chan
 * @author Ronald Monzillo
 */
public class GFServerConfigProvider implements AuthConfigProvider {

    public static final Logger logger = Logger.getLogger(GFServerConfigProvider.class.getName());

    protected AuthConfigFactory factory;
    
    public GFServerConfigProvider(AuthConfigFactory factory) {
        this.factory = factory;
    }

    public GFServerConfigProvider(Map properties, AuthConfigFactory factory) {
        this.factory = factory;
    }

    @Override
    public ClientAuthConfig getClientAuthConfig(String layer, String appContext, CallbackHandler handler) throws AuthException {
        return new GFClientAuthConfig(this, layer, appContext, handler);
    }

    @Override
    public ServerAuthConfig getServerAuthConfig(String layer, String appContext, CallbackHandler handler) throws AuthException {
        return new GFServerAuthConfig(this, layer, appContext, handler);
    }

    @Override
    public void refresh() {
        ModuleConfigurationManager.loadParser(this, factory, null);
    }

}
