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

package org.glassfish.epicyro.config.module.configprovider;

import java.util.HashSet;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import javax.security.auth.callback.CallbackHandler;

import org.glassfish.epicyro.config.delegate.MessagePolicyDelegate;
import org.glassfish.epicyro.config.helper.EpochCarrier;
import org.glassfish.epicyro.config.helper.LogManager;
import org.glassfish.epicyro.config.helper.ModulesManager;
import org.glassfish.epicyro.config.module.config.ClientAuthConfigImpl;
import org.glassfish.epicyro.config.module.config.ServerAuthConfigImpl;

import jakarta.security.auth.message.AuthException;
import jakarta.security.auth.message.config.AuthConfigFactory;
import jakarta.security.auth.message.config.AuthConfigFactory.RegistrationContext;
import jakarta.security.auth.message.config.AuthConfigProvider;
import jakarta.security.auth.message.config.ClientAuthConfig;
import jakarta.security.auth.message.config.ServerAuthConfig;
import jakarta.security.auth.message.module.ClientAuthModule;
import jakarta.security.auth.message.module.ServerAuthModule;

/**
 *
 * @author Ron Monzillo
 */
public abstract class BaseAuthConfigProvider implements AuthConfigProvider {

    public static final String LAYER_NAME_KEY = "message.layer";
    public static final String ALL_LAYERS = "*";
    public static final String LOGGER_NAME_KEY = "logger.name";
    public static final String AUTH_MODULE_KEY = "auth.module.type";
    public static final String SERVER_AUTH_MODULE = "server.auth.module";
    public static final String CLIENT_AUTH_MODULE = "client.auth.module";

    private ReentrantReadWriteLock instanceReadWriteLock = new ReentrantReadWriteLock();
    private Lock writeLock = instanceReadWriteLock.writeLock();
    private HashSet<String> selfRegistered = new HashSet<>();
    private EpochCarrier epochCarrier = new EpochCarrier();

    @Override
    public ClientAuthConfig getClientAuthConfig(String layer, String appContext, CallbackHandler callbackHandler) throws AuthException {
        return new ClientAuthConfigImpl(getLoggerName(), epochCarrier, getModulesManager(appContext, true), getMessagePolicyDelegate(appContext), layer,
                appContext, getClientCallbackHandler(callbackHandler));
    }

    @Override
    public ServerAuthConfig getServerAuthConfig(String layer, String appContext, CallbackHandler callbackHandler) throws AuthException {
        return new ServerAuthConfigImpl(getLoggerName(), epochCarrier, getModulesManager(appContext, true), getMessagePolicyDelegate(appContext), layer,
                appContext, getServerCallbackHandler(callbackHandler));
    }

    public boolean contextsAreEqual(RegistrationContext context1, RegistrationContext context2) {
        if (context1 == null || context2 == null) {
            return false;
        }

        if (context1.isPersistent() != context2.isPersistent()) {
            return false;
        }

        if (!context1.getAppContext().equals(context2.getAppContext())) {
            return false;
        }

        if (!context1.getMessageLayer().equals(context2.getMessageLayer())) {
            return false;
        }

        if (!context1.getDescription().equals(context2.getDescription())) {
            return false;
        }

        return true;
    }

    @Override
    public void refresh() {
        epochCarrier.increment();
        selfRegister();
    }

    public String getLoggerName() {
        return getProperty(LOGGER_NAME_KEY, BaseAuthConfigProvider.class.getName());
    }

    public LogManager getLogManager() {
        return new LogManager(getLoggerName());
    }

    protected final String getProperty(String key, String defaultValue) {
        Map<String, ?> properties = getProperties();
        if (properties != null && properties.containsKey(key)) {
            return (String) properties.get(key);
        }

        return defaultValue;
    }

    protected String getLayer() {
        return getProperty(LAYER_NAME_KEY, ALL_LAYERS);
    }

    protected Class<?>[] getModuleTypes() {
        Class<?>[] moduleTypes = new Class[] { ServerAuthModule.class, ClientAuthModule.class };

        Map<String, ?> properties = getProperties();
        if (properties.containsKey(AUTH_MODULE_KEY)) {
            String keyValue = (String) properties.get(AUTH_MODULE_KEY);

            if (SERVER_AUTH_MODULE.equals(keyValue)) {
                moduleTypes = new Class[] { ServerAuthModule.class };
            } else if (CLIENT_AUTH_MODULE.equals(keyValue)) {
                moduleTypes = new Class[] { ClientAuthModule.class };
            }
        }

        return moduleTypes;
    }

    protected void selfRegister() {
        if (getFactory() != null) {
            writeLock.lock();
            try {
                RegistrationContext[] contexts = getSelfRegistrationContexts();
                if (!selfRegistered.isEmpty()) {
                    HashSet<String> toBeUnregistered = new HashSet<String>();
                    // get the current self-registrations
                    String[] registrationIDs = getFactory().getRegistrationIDs(this);

                    for (String registrationId : registrationIDs) {
                        if (selfRegistered.contains(registrationId)) {
                            RegistrationContext context = getFactory().getRegistrationContext(registrationId);
                            if (context != null && !context.isPersistent()) {
                                toBeUnregistered.add(registrationId);
                            }
                        }
                    }

                    // remove self-registrations that already exist and should continue
                    for (String registrationId : toBeUnregistered) {
                        RegistrationContext context = getFactory().getRegistrationContext(registrationId);
                        for (int j = 0; j < contexts.length; j++) {
                            if (contextsAreEqual(contexts[j], context)) {
                                toBeUnregistered.remove(registrationId);
                                contexts[j] = null;
                            }
                        }
                    }

                    // unregister those that should not continue to exist
                    for (String registrationId : toBeUnregistered) {
                        selfRegistered.remove(registrationId);
                        getFactory().removeRegistration(registrationId);
                    }
                }

                // add new self-segistrations
                for (RegistrationContext context : contexts) {
                    if (context != null) {
                        String id = getFactory().registerConfigProvider(this, context.getMessageLayer(), context.getAppContext(), context.getDescription());
                        selfRegistered.add(id);
                    }
                }
            } finally {
                writeLock.unlock();
            }

        }
    }

    protected CallbackHandler getClientCallbackHandler(CallbackHandler callbackHandler) throws AuthException {
        if (callbackHandler == null) {
            throw (AuthException) new AuthException("AuthConfigProvider does not support null Client Callbackhandler")
                    .initCause(new UnsupportedOperationException());
        }

        return callbackHandler;
    }

    protected CallbackHandler getServerCallbackHandler(CallbackHandler callbackHandler) throws AuthException {
        if (callbackHandler == null) {
            throw (AuthException) new AuthException("AuthConfigProvider does not support null Server Callbackhandler")
                    .initCause(new UnsupportedOperationException());
        }

        return callbackHandler;
    }

    public abstract Map<String, ?> getProperties();

    public abstract AuthConfigFactory getFactory();

    public abstract RegistrationContext[] getSelfRegistrationContexts();

    public abstract ModulesManager getModulesManager(String appContext, boolean returnNullContexts) throws AuthException;

    public abstract MessagePolicyDelegate getMessagePolicyDelegate(String appContext) throws AuthException;

}
