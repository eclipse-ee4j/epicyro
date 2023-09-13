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

import static org.omnifaces.eleos.config.helper.HttpServletConstants.SERVER;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;

import org.omnifaces.eleos.config.helper.ModuleConfigurationManager;
import org.omnifaces.eleos.config.module.context.GFServerAuthContext;
import org.omnifaces.eleos.data.AuthModuleInstanceHolder;

import jakarta.security.auth.message.AuthException;
import jakarta.security.auth.message.config.AuthConfigProvider;
import jakarta.security.auth.message.config.ServerAuthConfig;
import jakarta.security.auth.message.config.ServerAuthContext;

public class GFServerAuthConfig extends GFAuthConfig implements ServerAuthConfig {

    public GFServerAuthConfig(ModuleConfigurationManager moduleConfigurationManager, AuthConfigProvider provider, String layer, String appContext, CallbackHandler handler) {
        super(moduleConfigurationManager, provider, layer, appContext, handler, SERVER);
    }

    @Override
    public ServerAuthContext getAuthContext(String authContextId, Subject serviceSubject, @SuppressWarnings("rawtypes") Map properties) throws AuthException {
        @SuppressWarnings("unchecked")
        AuthModuleInstanceHolder authModuleInstanceHolder = getAuthModuleInstanceHolder(authContextId, properties);
        if (authModuleInstanceHolder == null || authModuleInstanceHolder.getModule() == null) {
            return null;
        }

        return new GFServerAuthContext(authModuleInstanceHolder.getModule());
    }
}