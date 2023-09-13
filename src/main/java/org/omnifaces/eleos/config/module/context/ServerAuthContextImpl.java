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

package org.omnifaces.eleos.config.module.context;

import static java.util.logging.Level.FINE;
import static java.util.logging.Level.SEVERE;
import static java.util.logging.Level.WARNING;
import static javax.security.auth.message.AuthStatus.SEND_FAILURE;
import static javax.security.auth.message.AuthStatus.SEND_SUCCESS;
import static javax.security.auth.message.AuthStatus.SUCCESS;

import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;

import org.omnifaces.eleos.config.delegate.MessagePolicyDelegate;
import org.omnifaces.eleos.config.helper.ModulesManager;

public class ServerAuthContextImpl implements ServerAuthContext {

    private final static AuthStatus[] validateRequestSuccessValues = { SUCCESS, SEND_SUCCESS };
    private final static AuthStatus[] secureResponseSuccessValues = { SEND_SUCCESS };

    private String loggerName;

    private ModulesManager modulesManager;

    private MessagePolicyDelegate policyDelegate;

    private String appContext;

    private CallbackHandler callbackHandler;

    private String authContextID;

    private Map<String, ?> properties;

    private ServerAuthModule[] serverAuthModules;


    public ServerAuthContextImpl(String loggerName, ModulesManager modulesManager,
            MessagePolicyDelegate policyDelegate, String appContext, CallbackHandler callbackHandler, String authContextID, Map<String, ?> properties) {

        this.loggerName = loggerName;
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

            if (isLoggable(FINE)) {
                logIfLevel(FINE, null, "ServerAuthContext: ", authContextID, "of AppContext: ", appContext,
                        "calling vaidateRequest on module");
            }

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

            if (isLoggable(FINE)) {
                logIfLevel(FINE, null, "ServerAuthContext: ", authContextID, "of AppContext: ", appContext,
                        "calling secureResponse on module");
            }

            status[i] = serverAuthModules[i].secureResponse(messageInfo, serviceSubject);

            if (modulesManager.shouldStopProcessingModules(secureResponseSuccessValues, i, status[i])) {
                return modulesManager.getReturnStatus(secureResponseSuccessValues, SEND_FAILURE, status, i);
            }
        }

        return modulesManager.getReturnStatus(secureResponseSuccessValues, SEND_FAILURE, status, status.length - 1);
    }

    @Override
    public void cleanSubject(MessageInfo arg0, Subject arg1) throws AuthException {
        for (int i = 0; i < serverAuthModules.length; i++) {
            if (serverAuthModules[i] == null) {
                continue;
            }

            if (isLoggable(Level.FINE)) {
                logIfLevel(Level.FINE, null, "ServerAuthContext: ", authContextID, "of AppContext: ", appContext,
                        "calling cleanSubject on module");
            }

            serverAuthModules[i].cleanSubject(arg0, arg1);
        }
    }

    private ServerAuthModule[] getServerAuthModules() {
        try {
            ServerAuthModule[] serverAuthModules;

            try {
                serverAuthModules = modulesManager.getModules(new ServerAuthModule[0], authContextID);
            } catch (AuthException ae) {
                logIfLevel(SEVERE, ae, "ServerAuthContext: ", authContextID, "of AppContext: ", appContext,
                        "unable to load server auth modules");
                throw ae;
            }

            MessagePolicy requestPolicy = policyDelegate.getRequestPolicy(authContextID, properties);
            MessagePolicy responsePolicy = policyDelegate.getResponsePolicy(authContextID, properties);

            boolean noModules = true;
            for (int i = 0; i < serverAuthModules.length; i++) {
                if (serverAuthModules[i] != null) {
                    if (isLoggable(FINE)) {
                        logIfLevel(FINE, null, "ServerAuthContext: ", authContextID, "of AppContext: ", appContext,
                                "initializing module");
                    }

                    noModules = false;
                    checkMessageTypes(serverAuthModules[i].getSupportedMessageTypes());

                    serverAuthModules[i].initialize(
                            requestPolicy, responsePolicy,
                            callbackHandler, modulesManager.getInitProperties(i, properties));
                }
            }

            if (noModules) {
                logIfLevel(WARNING, null, "ServerAuthContext: ", authContextID, "of AppContext: ", appContext,
                        "contains no Auth Modules");
            }

            return serverAuthModules;
        } catch (AuthException e) {
            throw new IllegalStateException(e);
        }
    }

    protected boolean isLoggable(Level level) {
        return Logger.getLogger(loggerName).isLoggable(level);
    }

    protected void logIfLevel(Level level, Throwable t, String... msgParts) {
        Logger logger = Logger.getLogger(loggerName);

        if (logger.isLoggable(level)) {
            StringBuilder messageBuffer = new StringBuilder("");

            for (String m : msgParts) {
                messageBuffer.append(m);
            }

            String msg = messageBuffer.toString();

            if (!msg.isEmpty() && t != null) {
                logger.log(level, msg, t);
            } else if (!msg.isEmpty()) {
                logger.log(level, msg);
            }
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
