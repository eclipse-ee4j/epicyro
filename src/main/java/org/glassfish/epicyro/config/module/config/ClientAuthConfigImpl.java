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

package org.glassfish.epicyro.config.module.config;

import static java.util.logging.Level.FINE;
import static java.util.logging.Level.SEVERE;
import static java.util.logging.Level.WARNING;
import static jakarta.security.auth.message.AuthStatus.SEND_FAILURE;
import static jakarta.security.auth.message.AuthStatus.SEND_SUCCESS;
import static jakarta.security.auth.message.AuthStatus.SUCCESS;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;

import org.glassfish.epicyro.config.delegate.MessagePolicyDelegate;
import org.glassfish.epicyro.config.helper.EpochCarrier;
import org.glassfish.epicyro.config.helper.ModulesManager;

import jakarta.security.auth.message.AuthException;
import jakarta.security.auth.message.AuthStatus;
import jakarta.security.auth.message.MessageInfo;
import jakarta.security.auth.message.MessagePolicy;
import jakarta.security.auth.message.config.ClientAuthConfig;
import jakarta.security.auth.message.config.ClientAuthContext;
import jakarta.security.auth.message.module.ClientAuthModule;

/**
 *
 * @author Ron Monzillo
 */
public class ClientAuthConfigImpl extends BaseAuthConfigImpl implements ClientAuthConfig {

    private final static AuthStatus[] validateResponseSuccessValues = { SUCCESS };
    private final static AuthStatus[] secureResponseSuccessValues = { SEND_SUCCESS };

    private Map<String, Map<Integer, ClientAuthContext>> contextMap;
    private ModulesManager authContextHelper;

    public ClientAuthConfigImpl(String loggerName, EpochCarrier providerEpoch, ModulesManager acHelper,
            MessagePolicyDelegate mpDelegate, String layer, String appContext, CallbackHandler cbh) throws AuthException {
        super(loggerName, providerEpoch, mpDelegate, layer, appContext, cbh);

        this.authContextHelper = acHelper;
    }

    @Override
    protected void initializeContextMap() {
        contextMap = new HashMap<>();
    }

    protected void refreshContextHelper() {
        authContextHelper.refresh();
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <M> M createAuthContext(String authContextID, Map<String, ?> properties) throws AuthException {

        if (!authContextHelper.isProtected(new ClientAuthModule[0], authContextID)) {
            return null;
        }

        ClientAuthContext context = new ClientAuthContext() {

            ClientAuthModule[] module = init();

            ClientAuthModule[] init() throws AuthException {

                ClientAuthModule[] clientModules;
                try {
                    clientModules = authContextHelper.getModules(new ClientAuthModule[0], authContextID);
                } catch (AuthException ae) {
                    logIfLevel(SEVERE, ae, "ClientAuthContext: ", authContextID, "of AppContext: ", getAppContext(),
                            "unable to load client auth modules");
                    throw ae;
                }

                MessagePolicy requestPolicy = policyDelegate.getRequestPolicy(authContextID, properties);
                MessagePolicy responsePolicy = policyDelegate.getResponsePolicy(authContextID, properties);

                boolean noModules = true;
                for (int i = 0; i < clientModules.length; i++) {
                    if (clientModules[i] != null) {
                        if (isLoggable(FINE)) {
                            logIfLevel(FINE, null, "ClientAuthContext: ", authContextID, "of AppContext: ", getAppContext(),
                                    "initializing module");
                        }

                        noModules = false;
                        checkMessageTypes(clientModules[i].getSupportedMessageTypes());

                        clientModules[i].initialize(requestPolicy, responsePolicy, callbackHandler,
                                authContextHelper.getInitProperties(i, properties));
                    }
                }

                if (noModules) {
                    logIfLevel(WARNING, null, "CLientAuthContext: ", authContextID, "of AppContext: ", getAppContext(),
                            "contains no Auth Modules");
                }

                return clientModules;
            }

            @Override
            public AuthStatus validateResponse(MessageInfo arg0, Subject arg1, Subject arg2) throws AuthException {
                AuthStatus[] status = new AuthStatus[module.length];

                for (int i = 0; i < module.length; i++) {
                    if (module[i] == null) {
                        continue;
                    }

                    if (isLoggable(FINE)) {
                        logIfLevel(FINE, null, "ClientAuthContext: ", authContextID, "of AppContext: ", getAppContext(),
                                "calling vaidateResponse on module");
                    }

                    status[i] = module[i].validateResponse(arg0, arg1, arg2);

                    if (authContextHelper.shouldStopProcessingModules(validateResponseSuccessValues, i, status[i])) {
                        return authContextHelper.getReturnStatus(validateResponseSuccessValues, SEND_FAILURE, status, i);
                    }
                }

                return authContextHelper.getReturnStatus(validateResponseSuccessValues, SEND_FAILURE, status, status.length - 1);
            }

            @Override
            public AuthStatus secureRequest(MessageInfo arg0, Subject arg1) throws AuthException {
                AuthStatus[] status = new AuthStatus[module.length];
                for (int i = 0; i < module.length; i++) {
                    if (module[i] == null) {
                        continue;
                    }

                    if (isLoggable(FINE)) {
                        logIfLevel(FINE, null, "ClientAuthContext: ", authContextID, "of AppContext: ", getAppContext(),
                                "calling secureResponse on module");
                    }

                    status[i] = module[i].secureRequest(arg0, arg1);

                    if (authContextHelper.shouldStopProcessingModules(secureResponseSuccessValues, i, status[i])) {
                        return authContextHelper.getReturnStatus(secureResponseSuccessValues, AuthStatus.SEND_FAILURE, status, i);
                    }
                }
                return authContextHelper.getReturnStatus(secureResponseSuccessValues, AuthStatus.SEND_FAILURE, status, status.length - 1);
            }

            @Override
            public void cleanSubject(MessageInfo arg0, Subject arg1) throws AuthException {
                for (int i = 0; i < module.length; i++) {
                    if (module[i] == null) {
                        continue;
                    }

                    if (isLoggable(FINE)) {
                        logIfLevel(FINE, null, "ClientAuthContext: ", authContextID, "of AppContext: ", getAppContext(),
                                "calling cleanSubject on module");
                    }

                    module[i].cleanSubject(arg0, arg1);
                }
            }
        };

        return (M) context;
    }

    @Override
    @SuppressWarnings("unchecked")
    public ClientAuthContext getAuthContext(String authContextID, Subject subject, @SuppressWarnings("rawtypes") Map properties)
            throws AuthException {
        return super.getContext(contextMap, authContextID, subject, properties);
    }

    @Override
    public boolean isProtected() {
        return !authContextHelper.returnsNullContexts() || policyDelegate.isProtected();
    }
}
