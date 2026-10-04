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

package org.glassfish.epicyro.config.module.config;

import java.lang.System.Logger;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;

import org.glassfish.epicyro.config.delegate.MessagePolicyDelegate;
import org.glassfish.epicyro.config.helper.EpochCarrier;

import static java.lang.System.Logger.Level.DEBUG;

import jakarta.security.auth.message.AuthException;
import jakarta.security.auth.message.MessageInfo;
import jakarta.security.auth.message.config.AuthConfig;

/**
 * Base class for the {@link ClientAuthConfigImpl} and {@link ServerAuthConfigImpl}.
 *
 * @author Ron Monzillo
 */
public abstract class BaseAuthConfigImpl implements AuthConfig {

    private static final Logger LOG = System.getLogger(BaseAuthConfigImpl.class.getName());

    EpochCarrier providerEpoch;
    long epoch;
    MessagePolicyDelegate policyDelegate;
    String layer;
    String appContext;
    CallbackHandler callbackHandler;

    private final ReentrantReadWriteLock instanceReadWriteLock = new ReentrantReadWriteLock();
    private final Lock instanceReadLock = instanceReadWriteLock.readLock();
    private final Lock instanceWriteLock = instanceReadWriteLock.writeLock();

    public BaseAuthConfigImpl(EpochCarrier providerEpoch, MessagePolicyDelegate policyDelegate, String layer,
            String appContext, CallbackHandler callbackHandler) throws AuthException {
        this.providerEpoch = providerEpoch;
        this.policyDelegate = policyDelegate;
        this.layer = layer;
        this.appContext = appContext;
        this.callbackHandler = callbackHandler;

        initialize();
    }

    @Override
    public String getMessageLayer() {
        return layer;
    }

    @Override
    public String getAppContext() {
        return appContext;
    }

    @Override
    public String getAuthContextID(MessageInfo messageInfo) {
        return policyDelegate.getAuthContextID(messageInfo);
    }

    @Override
    public void refresh() {
        try {
            initialize();
        } catch (AuthException ae) {
            throw new RuntimeException(ae);
        }
    }

    private void initialize() throws AuthException {
        instanceWriteLock.lock();
        try {
            epoch = providerEpoch.getEpoch();
            initializeContextMap();
        } finally {
            instanceWriteLock.unlock();
        }
    }

    private void doRefreshIfNeeded() {
        boolean hasChanged = false;
        instanceReadLock.lock();
        try {
            hasChanged = providerEpoch.hasChanged(epoch);
        } finally {
            instanceReadLock.unlock();
        }

        if (hasChanged) {
            refresh();
        }
    }

    private Integer getHashCode(Map<String, ?> properties) {
        if (properties == null) {
            return Integer.valueOf("0");
        }

        return Integer.valueOf(properties.hashCode());
    }

    private <M> M getContextFromMap(Map<String, Map<Integer, M>> contextMap, String authContextID, Map<String, ?> properties) {
        M context = null;

        Map<Integer, M> internalMap = contextMap.get(authContextID);
        if (internalMap != null) {
            context = internalMap.get(getHashCode(properties));
        }

        if (context != null) {
            LOG.log(DEBUG, "AuthContextID found in Map: {0}", authContextID);
        }

        return context;
    }

    protected final <M> M getContext(Map<String, Map<Integer, M>> contextMap, String authContextID, Subject subject, Map<String, ?> properties)
            throws AuthException {

        M context = null;

        doRefreshIfNeeded();

        instanceReadLock.lock();
        try {
            context = getContextFromMap(contextMap, authContextID, properties);
            if (context != null) {
                return context;
            }
        } finally {
            instanceReadLock.unlock();
        }

        instanceWriteLock.lock();
        try {
            context = getContextFromMap(contextMap, authContextID, properties);
            if (context == null) {

                context = (M) createAuthContext(authContextID, properties);

                Map<Integer, M> internalMap = contextMap.get(authContextID);
                if (internalMap == null) {
                    internalMap = new HashMap<>();
                    contextMap.put(authContextID, internalMap);
                }

                internalMap.put(getHashCode(properties), context);
            }
            return context;
        } finally {
            instanceWriteLock.unlock();
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

    /**
     * Only called from initialize (while lock is held).
     */
    protected abstract void initializeContextMap();

    protected abstract <M> M createAuthContext(String authContextID, Map<String, ?> properties) throws AuthException;
}
