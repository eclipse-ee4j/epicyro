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

package org.glassfish.epicyro.config.module.context;

import jakarta.security.auth.message.AuthException;
import jakarta.security.auth.message.AuthStatus;
import jakarta.security.auth.message.MessageInfo;
import jakarta.security.auth.message.MessagePolicy;
import jakarta.security.auth.message.config.ServerAuthContext;
import jakarta.security.auth.message.module.ServerAuthModule;

import java.lang.System.Logger;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;

import org.glassfish.epicyro.config.delegate.MessagePolicyDelegate;
import org.glassfish.epicyro.config.helper.ModulesManager;

import static jakarta.security.auth.message.AuthStatus.SEND_FAILURE;
import static jakarta.security.auth.message.AuthStatus.SEND_SUCCESS;
import static jakarta.security.auth.message.AuthStatus.SUCCESS;
import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.ERROR;
import static java.lang.System.Logger.Level.WARNING;

public class ServerAuthContextImpl implements ServerAuthContext {

    private static final Logger LOG = System.getLogger(ServerAuthContextImpl.class.getName());

    private final static AuthStatus[] validateRequestSuccessValues = { SUCCESS, SEND_SUCCESS };
    private final static AuthStatus[] secureResponseSuccessValues = { SEND_SUCCESS };

    private final ModulesManager modulesManager;
    private final MessagePolicyDelegate policyDelegate;
    private final String appContext;
    private final CallbackHandler callbackHandler;
    private final String authContextID;
    private final Map<String, ?> properties;
    private final ServerAuthModule[] serverAuthModules;


    public ServerAuthContextImpl(ModulesManager modulesManager, MessagePolicyDelegate policyDelegate, String appContext,
        CallbackHandler callbackHandler, String authContextID, Map<String, ?> properties) {
        this.modulesManager = modulesManager;
        this.policyDelegate = policyDelegate;
        this.appContext = appContext;
        this.callbackHandler = callbackHandler;
        this.authContextID = authContextID;
        this.properties = properties;

        this.serverAuthModules = getServerAuthModules();
    }

    @Override
    public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
        AuthStatus[] status = new AuthStatus[serverAuthModules.length];

        for (int moduleNumber = 0; moduleNumber < serverAuthModules.length; moduleNumber++) {
            if (serverAuthModules[moduleNumber] == null) {
                continue;
            }

            LOG.log(DEBUG, "ServerAuthContext: {0} of AppContext: {1} - calling vaidateRequest on module.", authContextID, appContext);

            status[moduleNumber] = serverAuthModules[moduleNumber].validateRequest(messageInfo, clientSubject, serviceSubject);

            if (modulesManager.shouldStopProcessingModules(validateRequestSuccessValues, moduleNumber, status[moduleNumber])) {
                return modulesManager.getReturnStatus(validateRequestSuccessValues, SEND_FAILURE, status, moduleNumber);
            }
        }

        return modulesManager.getReturnStatus(validateRequestSuccessValues, SEND_FAILURE, status, status.length - 1);
    }

    @Override
    public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
        AuthStatus[] status = new AuthStatus[serverAuthModules.length];

        for (int i = 0; i < serverAuthModules.length; i++) {
            if (serverAuthModules[i] == null) {
                continue;
            }

            LOG.log(DEBUG, "ServerAuthContext: {0} of AppContext: {1} - calling secureResponse on module.", authContextID, appContext);

            status[i] = serverAuthModules[i].secureResponse(messageInfo, serviceSubject);

            if (modulesManager.shouldStopProcessingModules(secureResponseSuccessValues, i, status[i])) {
                return modulesManager.getReturnStatus(secureResponseSuccessValues, SEND_FAILURE, status, i);
            }
        }

        return modulesManager.getReturnStatus(secureResponseSuccessValues, SEND_FAILURE, status, status.length - 1);
    }

    @Override
    public void cleanSubject(MessageInfo arg0, Subject arg1) throws AuthException {
        for (ServerAuthModule serverAuthModule : serverAuthModules) {
            if (serverAuthModule == null) {
                continue;
            }

            LOG.log(DEBUG, "ServerAuthContext: {0} of AppContext: {1} - calling cleanSubject on module.", authContextID, appContext);

            serverAuthModule.cleanSubject(arg0, arg1);
        }
    }

    private ServerAuthModule[] getServerAuthModules() {
        try {
            ServerAuthModule[] serverAuthModules;

            try {
                serverAuthModules = modulesManager.getModules(new ServerAuthModule[0], authContextID);
            } catch (AuthException ae) {
                LOG.log(ERROR, () -> "ServerAuthContext: " + authContextID + " of AppContext: " + appContext
                    + " - unable to load server auth modules", ae);
                throw ae;
            }

            MessagePolicy requestPolicy = policyDelegate.getRequestPolicy(authContextID, properties);
            MessagePolicy responsePolicy = policyDelegate.getResponsePolicy(authContextID, properties);

            boolean noModules = true;
            for (int i = 0; i < serverAuthModules.length; i++) {
                if (serverAuthModules[i] != null) {
                    LOG.log(DEBUG, "ServerAuthContext: {0} of AppContext: {1} - initializing module.", authContextID, appContext);

                    noModules = false;
                    checkMessageTypes(serverAuthModules[i].getSupportedMessageTypes());

                    serverAuthModules[i].initialize(
                            requestPolicy, responsePolicy,
                            callbackHandler, modulesManager.getInitProperties(i, properties));
                }
            }

            if (noModules) {
                LOG.log(WARNING, "ServerAuthContext: {0} of AppContext: {1} - contains no Auth Modules!", authContextID, appContext);
            }

            return serverAuthModules;
        } catch (AuthException e) {
            throw new IllegalStateException(e);
        }
    }


    protected void checkMessageTypes(Class<?>[] supportedMessageTypes) throws AuthException {
        Class<?>[] requiredMessageTypes = policyDelegate.getMessageTypes();
        for (Class<?> requiredType : requiredMessageTypes) {
            boolean supported = false;
            for (Class<?> supportedType : supportedMessageTypes) {
                if (requiredType.isAssignableFrom(supportedType)) {
                    supported = true;
                }
            }

            if (!supported) {
                throw new AuthException("module does not support message type: " + requiredType.getName());
            }
        }
    }
}
