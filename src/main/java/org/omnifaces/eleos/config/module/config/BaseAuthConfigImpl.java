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

import static java.util.logging.Level.FINE;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.AuthConfig;

import org.omnifaces.eleos.config.delegate.MessagePolicyDelegate;
import org.omnifaces.eleos.config.helper.EpochCarrier;

/**
 * Base class for the {@link ClientAuthConfigImpl} and {@link ServerAuthConfigImpl}.
 *
 * @author Ron Monzillo
 */
public abstract class BaseAuthConfigImpl implements AuthConfig {

    String loggerName;
    EpochCarrier providerEpoch;
    long epoch;
    MessagePolicyDelegate policyDelegate;
    String layer;
    String appContext;
    CallbackHandler callbackHandler;

    private ReentrantReadWriteLock instanceReadWriteLock = new ReentrantReadWriteLock();
    private Lock instanceReadLock = instanceReadWriteLock.readLock();
    private Lock instanceWriteLock = instanceReadWriteLock.writeLock();

    public BaseAuthConfigImpl(String loggerName, EpochCarrier providerEpoch, MessagePolicyDelegate policyDelegate, String layer,
            String appContext, CallbackHandler callbackHandler) throws AuthException {
        this.loggerName = loggerName;
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
            this.epoch = providerEpoch.getEpoch();
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
            if (isLoggable(FINE)) {
                logIfLevel(FINE, null, "AuthContextID found in Map: ", authContextID);
            }
        }

        return context;
    }

    @SuppressWarnings("unchecked")
    protected final <M> M getContext(Map<String, Map<Integer, M>> contextMap, String authContextID, Subject subject,
            Map<String, ?> properties)
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
                    internalMap = new HashMap<Integer, M>();
                    contextMap.put(authContextID, internalMap);
                }

                internalMap.put(getHashCode(properties), context);
            }
            return context;
        } finally {
            instanceWriteLock.unlock();
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

    /**
     * Only called from initialize (while lock is held).
     */
    protected abstract void initializeContextMap();

    protected abstract <M> M createAuthContext(String authContextID, Map<String, ?> properties) throws AuthException;
}
