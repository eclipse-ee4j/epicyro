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

package org.omnifaces.eleos.services;


import static java.lang.Boolean.TRUE;
import static javax.security.auth.message.AuthStatus.SUCCESS;
import static javax.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
import static org.omnifaces.eleos.config.helper.HttpServletConstants.IS_MANDATORY;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Function;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.AuthConfig;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.AuthConfigFactory.RegistrationContext;
import javax.security.auth.message.config.AuthConfigProvider;
import javax.security.auth.message.config.ClientAuthConfig;
import javax.security.auth.message.config.ClientAuthContext;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.omnifaces.eleos.config.helper.AuthMessagePolicy;
import org.omnifaces.eleos.config.helper.Caller;
import org.omnifaces.eleos.config.servlet.HttpMessageInfo;

/**
 */
public class BaseAuthenticationService {

    protected static final AuthConfigFactory factory = AuthConfigFactory.getFactory();

    private ReadWriteLock readWriteLock;
    private Lock readLock;
    private Lock writeLock;

    protected String layer;
    protected String appCtxt;
    protected Map<String, ?> map;
    protected CallbackHandler callbackHandler;
    protected AuthConfigRegistrationWrapper listenerWrapper;

    protected void init(String layer, String appContext, Map<String, ?> map, CallbackHandler callbackHandler, RegistrationWrapperRemover removerDelegate) {
        this.layer = layer;
        this.appCtxt = appContext;
        this.map = map;
        this.callbackHandler = callbackHandler;
        if (this.callbackHandler == null) {
            this.callbackHandler = getCallbackHandler();
        }

        this.readWriteLock = new ReentrantReadWriteLock(true);
        this.readLock = readWriteLock.readLock();
        this.writeLock = readWriteLock.writeLock();

        listenerWrapper = new AuthConfigRegistrationWrapper(this.layer, this.appCtxt, removerDelegate);
    }

    public void setRegistrationId(String registrationId) {
        listenerWrapper.setRegistrationId(registrationId);
    }

    public AuthConfigRegistrationWrapper getRegistrationWrapper() {
        return listenerWrapper;
    }

    public void setRegistrationWrapper(AuthConfigRegistrationWrapper wrapper) {
        this.listenerWrapper = wrapper;
    }

    public AuthConfigRegistrationWrapper.AuthConfigRegistrationListener getRegistrationListener() {
        return listenerWrapper.getListener();
    }

    public void disable() {
        listenerWrapper.disable();
    }

    public Object getProperty(String key) {
        return map == null ? null : map.get(key);
    }

    public String getAppContextID() {
        return appCtxt;
    }

    public ClientAuthConfig getClientAuthConfig() throws AuthException {
        return (ClientAuthConfig) getAuthConfig(false);
    }

    public ServerAuthConfig getServerAuthConfig() throws AuthException {
        return (ServerAuthConfig) getAuthConfig(true);
    }

    public ClientAuthContext getClientAuthContext(MessageInfo info, Subject clientSubject) throws AuthException {
        ClientAuthConfig clientConfig = (ClientAuthConfig) getAuthConfig(false);
        if (clientConfig != null) {
            return clientConfig.getAuthContext(clientConfig.getAuthContextID(info), clientSubject, map);
        }

        return null;
    }
    
    public ServerAuthContext getServerAuthContext(MessageInfo info) throws AuthException {
        return getServerAuthContext(info, null);
    }

    public ServerAuthContext getServerAuthContext(MessageInfo info, Subject serviceSubject) throws AuthException {
        ServerAuthConfig serverAuthConfig = (ServerAuthConfig) getAuthConfig(true);
        if (serverAuthConfig != null) {
            return serverAuthConfig.getAuthContext(serverAuthConfig.getAuthContextID(info), serviceSubject, map);
        }

        return null;
    }

    protected AuthConfig getAuthConfig(AuthConfigProvider authConfigProvider, boolean isServer) throws AuthException {
        AuthConfig authConfig = null;

        if (authConfigProvider != null) {
            if (isServer) {
                authConfig = authConfigProvider.getServerAuthConfig(layer, appCtxt, callbackHandler);
            } else {
                authConfig = authConfigProvider.getClientAuthConfig(layer, appCtxt, callbackHandler);
            }
        }

        return authConfig;
    }

    protected AuthConfig getAuthConfig(boolean isServer) throws AuthException {

        ConfigData configData = null;
        AuthConfig authConfig = null;
        boolean disabled = false;
        AuthConfigProvider lastConfigProvider = null;

        try {
            readLock.lock();
            disabled = !listenerWrapper.isEnabled();
            if (!disabled) {
                configData = listenerWrapper.getConfigData();
                if (configData != null) {
                    authConfig = isServer ? configData.getServerConfig() : configData.getClientConfig();
                    lastConfigProvider = configData.getProvider();
                }
            }

        } finally {
            readLock.unlock();
            if (disabled || authConfig != null || (configData != null && lastConfigProvider == null)) {
                return authConfig;
            }
        }

        // d == null || (d != null && lastP != null && c == null)
        if (configData == null) {
            try {
                writeLock.lock();
                if (listenerWrapper.getConfigData() == null) {
                    AuthConfigProvider nextConfigProvider = factory.getConfigProvider(layer, appCtxt, getRegistrationListener());

                    if (nextConfigProvider != null) {
                        listenerWrapper.setConfigData(new ConfigData(nextConfigProvider, getAuthConfig(nextConfigProvider, isServer)));
                    } else {
                        listenerWrapper.setConfigData(new ConfigData());
                    }
                }
                configData = listenerWrapper.getConfigData();
            } finally {
                writeLock.unlock();
            }
        }

        return isServer ? configData.getServerConfig() : configData.getClientConfig();
    }

    /**
     * Check if there is a provider register for a given layer and appCtxt.
     */
    protected boolean hasExactMatchAuthProvider() {
        boolean exactMatch = false;

        AuthConfigProvider configProvider = factory.getConfigProvider(layer, appCtxt, null);

        if (configProvider != null) {
            for (String registrationId : factory.getRegistrationIDs(configProvider)) {
                RegistrationContext registrationContext = factory.getRegistrationContext(registrationId);
                if (layer.equals(registrationContext.getMessageLayer()) && appCtxt.equals(registrationContext.getAppContext())) {
                    exactMatch = true;
                    break;
                }
            }
        }

        return exactMatch;
    }

    /**
     * Get the callback default handler
     */
    protected CallbackHandler getCallbackHandler() {
       return AuthMessagePolicy.getDefaultCallbackHandler();
    }
    
    public Caller validateRequest(HttpServletRequest servletRequest, HttpServletResponse servletResponse, boolean calledFromAuthenticate, Function<HttpServletRequest, Boolean> isMandatoryFn) throws IOException {
        boolean isMandatory = true;
        
        Subject subject = new Subject();
        MessageInfo messageInfo = new HttpMessageInfo(servletRequest, servletResponse);
        
        try {
            isMandatory = isMandatoryFn.apply(servletRequest);

            if (isMandatory || calledFromAuthenticate) {
                setMandatory(messageInfo);
            }

            if (!SUCCESS.equals(getServerAuthContext(messageInfo).validateRequest(messageInfo, subject, null))) {
                return null;
            }
            
            return Caller.fromSubject(subject);

        } catch (AuthException | RuntimeException e) {
            servletResponse.setStatus(SC_INTERNAL_SERVER_ERROR);
        }
        
        return null;
    }
    
    @SuppressWarnings("unchecked")
    private void setMandatory(MessageInfo messageInfo) {
        messageInfo.getMap().put(IS_MANDATORY, TRUE.toString());
    }



}
