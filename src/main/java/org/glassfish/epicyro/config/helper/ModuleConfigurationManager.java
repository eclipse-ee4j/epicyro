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

package org.glassfish.epicyro.config.helper;

import static java.util.logging.Level.FINE;
import static org.glassfish.epicyro.config.helper.HttpServletConstants.CLIENT;
import static org.glassfish.epicyro.config.helper.HttpServletConstants.SERVER;
import static org.glassfish.epicyro.config.helper.ObjectUtils.newAuthModule;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.Logger;

import javax.security.auth.callback.CallbackHandler;

import org.glassfish.epicyro.config.factory.ConfigParser;
import org.glassfish.epicyro.data.AuthModuleBaseConfig;
import org.glassfish.epicyro.data.AuthModuleConfig;
import org.glassfish.epicyro.data.AuthModuleInstanceHolder;
import org.glassfish.epicyro.data.AuthModulesLayerConfig;

import jakarta.security.auth.message.AuthException;
import jakarta.security.auth.message.MessagePolicy;
import jakarta.security.auth.message.config.AuthConfigFactory;
import jakarta.security.auth.message.config.AuthConfigProvider;
import jakarta.security.auth.message.module.ClientAuthModule;
import jakarta.security.auth.message.module.ServerAuthModule;

public class ModuleConfigurationManager {

    public static final Logger logger = Logger.getLogger(ModuleConfigurationManager.class.getName());

    private final ReadWriteLock readWriteLock = new ReentrantReadWriteLock();
    private final OperationLock operationLock = new OperationLock(readWriteLock);

    private ConfigParser parser;
    private AuthConfigFactory factory;
    private AuthConfigProvider defaultProvider; // instance set as default for all layers

    // Map that keeps track of all default config providers being registered for each layer.
    // This is used to signal the removal of those providers when the manager is re-initialized and doesn't
    // support a previously available layer anymore.
    //
    // (In practice, does this *ever* happen? We normally only have the HttpServlet layer)
    private final Map<String, String> layerToDefaultProviderRegistrationMap = new HashMap<String, String>();

    public ModuleConfigurationManager(ConfigParser initParser, AuthConfigFactory initFactory, AuthConfigProvider initProvider) {
        init(initParser, initFactory, initProvider);
    }

    public void init(String initParserClassName, AuthConfigFactory initFactory, AuthConfigProvider initProvider) {
        init(ObjectUtils.<ConfigParser>createObject(initParserClassName), initFactory, initProvider);
    }

    public void init(ConfigParser initParser, AuthConfigFactory initFactory, AuthConfigProvider initProvider) {
        operationLock.doLocked(() -> parser == null, () -> {
            parser = initParser;
            loadParser(initProvider, initFactory, null);
        });

        if (initFactory != null) {
            operationLock.doLocked(() -> factory == null, () -> factory = initFactory);
        }

        if (initProvider != null) {
            operationLock.doLocked(() -> defaultProvider == null, () -> defaultProvider = initProvider);
        }

    }

    /**
     * this method is intended to be called by the admin configuration system when the corresponding config object has
     * changed.
     *
     * @param config a config object of type understood by the parserInstance. NOTE: there appears to be a thread saftey problem,
     * and this method will fail if a defaultProvider has not been established prior to its call.
     */
    public void loadConfigContext(Object config) {
        if (defaultProvider == null) {
            logger.severe("unableToLoad.noGlobalProvider");
            return;
        }

        if (!operationLock.doReadLocked(() -> factory != null)) {
            operationLock.doWriteLocked(() -> {
                if (factory == null) {
                    factory = AuthConfigFactory.getFactory();
                }
            });
        }

        loadParser(defaultProvider, factory, config);
    }

    public void loadParser(AuthConfigProvider defaultConfigProvider, AuthConfigFactory factory, Object config) {
        operationLock.doWriteLocked(() -> {
            try {
                parser.initialize(config);

                // Set the default provider for all layers supported by this parserInstance.

                if (factory != null && defaultConfigProvider != null) {
                    updateDefaultProviderForSupportedLayers(defaultConfigProvider, factory);
                }
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    /**
     * Instantiate and initialize module class
     */
    public AuthModuleInstanceHolder createAuthModuleInstance(AuthModuleBaseConfig authModuleConfig, CallbackHandler handler, String moduleType, Map<String, Object> properties) throws AuthException {
        try {
            // Instantiate module using no-arg constructor
            Object newModule = newAuthModule(authModuleConfig.getModuleClassName());

            // Merge the passed in options with the configured options
            Map<String, Object> moduleOptions = mergeModuleOptions(properties, authModuleConfig.getOptions());

            // Initialize Module
            if (SERVER.equals(moduleType)) {
                ((ServerAuthModule) newModule).initialize(authModuleConfig.getRequestPolicy(), authModuleConfig.getResponsePolicy(), handler, moduleOptions);
            } else { // CLIENT
                ((ClientAuthModule) newModule).initialize(authModuleConfig.getRequestPolicy(), authModuleConfig.getResponsePolicy(), handler, moduleOptions);
            }

            return new AuthModuleInstanceHolder(newModule, moduleOptions);
        } catch (Exception e) {
            if (e instanceof AuthException) {
                throw (AuthException) e;
            }

            throw (AuthException) new AuthException().initCause(e);
        }
    }

    public AuthModuleBaseConfig getAuthModuleConfig(String layer, String authModuleId, MessagePolicy requestPolicyIn, MessagePolicy responsePolicyIn, String authModuleType) {

        // get the parsed module config and DD information

        Map<String, AuthModulesLayerConfig> authModuleLayers = operationLock.doReadLocked(() -> parser.getAuthModuleLayers());
        if (authModuleLayers == null) {
            return null;
        }

        // Get the module config info for this layer

        AuthModulesLayerConfig authModulesLayerConfig = authModuleLayers.get(layer);
        if (authModulesLayerConfig == null || authModulesLayerConfig.getAuthModules() == null) {
            logger.log(FINE, () -> "module config has no auth modules configured for layer [" + layer + "]");
            return null;
        }

        // look up the DD's provider ID in the module config

        AuthModuleConfig authModuleConfig = null;
        if (authModuleId == null || (authModuleConfig = authModulesLayerConfig.getAuthModules().get(authModuleId)) == null) {

            // either the DD did not specify an auth module ID,
            // or the DD-specified auth module ID was not found/ in the module config.
            //
            // In either case, look for a default ID in the module config

            logger.log(FINE, () ->
                "DD did not specify auth module Id, or DD-specified Id for layer [" + layer + "] not found in config -- " +
                "attempting to look for default auth moduke Id");

            String defaultModuleID = getDefaultModuleId(authModuleType, authModulesLayerConfig);

            authModuleConfig = authModulesLayerConfig.getAuthModules().get(defaultModuleID);
            if (authModuleConfig == null) {

                // Did not find a default module ID

                logger.log(FINE, () -> "No default config Id for layer [" + layer + "]");

                return null;
            }
        }

        // We found the DD provider ID in the module config or we found a default module config

        // Check module-type
        if (authModuleConfig.getType().indexOf(authModuleType) < 0) {
            if (logger.isLoggable(FINE)) {
                logger.fine("Request type [" + authModuleType + "] does not match config type [" + authModuleConfig.getType() + "]");
            }

            return null;
        }

        // Check whether a policy is set
        MessagePolicy requestPolicy = getRequestPolicy(requestPolicyIn, responsePolicyIn, authModuleConfig);
        MessagePolicy responsePolicy = getResponsePolicy(requestPolicyIn, responsePolicyIn, authModuleConfig);

        // Optimization: if policy was not set, return null
        if (requestPolicy == null && responsePolicy == null) {
            logger.fine("no policy applies");
            return null;
        }

        // Return the configured modules with the correct policies

        AuthModuleBaseConfig newAuthModuleConfig = new AuthModuleBaseConfig(
                authModuleConfig.getModuleClassName(),
                requestPolicy,
                responsePolicy,
                authModuleConfig.getOptions());

        logger.log(FINE, () ->
            "getEntry for: " + layer + " -- " + authModuleId +
            "\n    module class: " + newAuthModuleConfig.getModuleClassName() +
            "\n    options: " + newAuthModuleConfig.getOptions() +
            "\n    request policy: " + newAuthModuleConfig.getRequestPolicy() +
            "\n    response policy: " + newAuthModuleConfig.getResponsePolicy());

        return newAuthModuleConfig;
    }

    private String getDefaultModuleId(String authModuleType, AuthModulesLayerConfig authModulesLayerConfig) {
        if (CLIENT.equals(authModuleType)) {
            return authModulesLayerConfig.getDefaultClientModuleId();
        }

        return authModulesLayerConfig.getDefaultServerModuleId();
    }

    private MessagePolicy getRequestPolicy(MessagePolicy requestPolicy, MessagePolicy responsePolicy, AuthModuleConfig authModuleConfig) {
        return requestPolicy != null || responsePolicy != null ? requestPolicy : authModuleConfig.getRequestPolicy(); // default;

    }

    private MessagePolicy getResponsePolicy(MessagePolicy requestPolicy, MessagePolicy responsePolicy, AuthModuleConfig authModuleConfig) {
        return requestPolicy != null || responsePolicy != null ? responsePolicy : authModuleConfig.getResponsePolicy(); // default;

    }

    private Map<String, Object> mergeModuleOptions(Map<String, Object> moduleOptions, Map<String, Object> configuredModuleOptions) {

        Map<String, Object> mergedModuleOptions = moduleOptions;

        if (configuredModuleOptions != null) {
            if (mergedModuleOptions == null) {
                mergedModuleOptions = new HashMap<>();
            } else {
                mergedModuleOptions = new HashMap<>(moduleOptions);
            }
            mergedModuleOptions.putAll(configuredModuleOptions);
        }

        return mergedModuleOptions;
    }

    private void updateDefaultProviderForSupportedLayers(AuthConfigProvider defaultConfigProvider, AuthConfigFactory factory) {

        Set<String> layers = parser.getLayersWithDefault();

        // Remove existing layers that are not in the new layers.

        for (String layer : layerToDefaultProviderRegistrationMap.keySet()) {
            if (!layers.contains(layer)) {
                factory.removeRegistration(layerToDefaultProviderRegistrationMap.remove(layer));
            }
        }

        // For all new layers for which we don't have registration yet, register the given
        // default config provider for the default (null) context.

        for (String layer : layers) {
            if (!layerToDefaultProviderRegistrationMap.containsKey(layer)) {
                layerToDefaultProviderRegistrationMap.put(
                    layer,
                    factory.registerConfigProvider(
                        defaultConfigProvider, layer, null, "GFServerConfigProvider: self registration"));
            }
        }
    }


}
