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

package org.omnifaces.elios.config.module.config;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;

import org.omnifaces.elios.config.delegate.MessagePolicyDelegate;
import org.omnifaces.elios.config.helper.EpochCarrier;
import org.omnifaces.elios.config.helper.ModulesManager;
import org.omnifaces.elios.config.module.context.ServerAuthContextImpl;

/**
 *
 * @author Ron Monzillo
 */
public class ServerAuthConfigImpl extends BaseAuthConfigImpl implements ServerAuthConfig {

    final static AuthStatus[] vR_SuccessValue = { AuthStatus.SUCCESS, AuthStatus.SEND_SUCCESS };
    final static AuthStatus[] sR_SuccessValue = { AuthStatus.SEND_SUCCESS };
    HashMap<String, HashMap<Integer, ServerAuthContext>> contextMap;
    ModulesManager acHelper;

    public ServerAuthConfigImpl(String loggerName, EpochCarrier providerEpoch, ModulesManager acHelper, MessagePolicyDelegate mpDelegate, String layer,
            String appContext, CallbackHandler cbh) throws AuthException {
        super(loggerName, providerEpoch, mpDelegate, layer, appContext, cbh);
        this.acHelper = acHelper;
        this.mpDelegate = mpDelegate;
    }

    @Override
    protected void initializeContextMap() {
        contextMap = new HashMap<String, HashMap<Integer, ServerAuthContext>>();
    }

    protected void refreshContextHelper() {
        acHelper.refresh();
    }

    @Override
    protected ServerAuthContext createAuthContext(final String authContextID, final Map properties) throws AuthException {

        if (!acHelper.isProtected(new ServerAuthModule[0], authContextID)) {
            return null;
        }

        // need to coordinate calls to CallerPrincipalCallback; expecially optional
        // modules that might reset the result of a required module
        return new ServerAuthContextImpl(properties);
    }

    @Override
    public ServerAuthContext getAuthContext(String authContextID, Subject subject, final Map properties) throws AuthException {
        return super.getContext(contextMap, authContextID, subject, properties);
    }

    @Override
    public boolean isProtected() {
        return (!acHelper.returnsNullContexts() || mpDelegate.isProtected());
    }
}
