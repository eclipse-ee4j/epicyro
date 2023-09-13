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

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;

import org.omnifaces.eleos.config.delegate.MessagePolicyDelegate;
import org.omnifaces.eleos.config.helper.EpochCarrier;
import org.omnifaces.eleos.config.helper.ModulesManager;
import org.omnifaces.eleos.config.module.context.ServerAuthContextImpl;

/**
 *
 * @author Ron Monzillo
 */
public class ServerAuthConfigImpl extends BaseAuthConfigImpl implements ServerAuthConfig {

    private Map<String, Map<Integer, ServerAuthContext>> contextMap;
    private ModulesManager authContextHelper;

    public ServerAuthConfigImpl(String loggerName, EpochCarrier providerEpoch, ModulesManager authContextHelper, MessagePolicyDelegate policyDelegate,
            String layer, String appContext, CallbackHandler callbackHandler) throws AuthException {

        super(loggerName, providerEpoch, policyDelegate, layer, appContext, callbackHandler);

        this.authContextHelper = authContextHelper;
        this.policyDelegate = policyDelegate;
    }

    @Override
    @SuppressWarnings("unchecked")
    public ServerAuthContext getAuthContext(String authContextID, Subject subject, @SuppressWarnings("rawtypes") Map properties) throws AuthException {
        return super.getContext(contextMap, authContextID, subject, properties);
    }

    @Override
    public boolean isProtected() {
        return !authContextHelper.returnsNullContexts() || policyDelegate.isProtected();
    }

    @Override
    protected void initializeContextMap() {
        contextMap = new HashMap<>();
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <M> M createAuthContext(String authContextID, Map<String, ?> properties) throws AuthException {

        if (!authContextHelper.isProtected(new ServerAuthModule[0], authContextID)) {
            return null;
        }

        // Need to coordinate calls to CallerPrincipalCallback; especially optional
        // modules that might reset the result of a required module
        return (M) new ServerAuthContextImpl(loggerName, authContextHelper, policyDelegate, getAppContext(), callbackHandler, authContextID, properties);
    }

}
