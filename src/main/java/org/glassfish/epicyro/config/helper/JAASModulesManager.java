/*
 * Copyright (c) 2022, 2024 OmniFish and/or its affiliates. All rights reserved.
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

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;
import static javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag.OPTIONAL;
import static javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag.REQUIRED;
import static javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag.REQUISITE;
import static javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag.SUFFICIENT;

import jakarta.security.auth.message.AuthException;
import jakarta.security.auth.message.AuthStatus;
import java.lang.System.Logger;
import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import org.glassfish.epicyro.config.jaas.ExtendedConfigFile;

/**
 *
 * @author Ron Monzillo
 */
public class JAASModulesManager extends ModulesManager {

    private static final Logger LOG = System.getLogger(JAASModulesManager.class.getName());

    private static final String DEFAULT_ENTRY_NAME = "other";
    private static final Class<?>[] PARAMS = {};
    private static final Object[] ARGS = {};

    private final ExtendedConfigFile jaasConfig;
    private final String appContext;

    // may be more than one delegate for a given jaas config file
    private final ReentrantReadWriteLock instanceReadWriteLock = new ReentrantReadWriteLock();
    private final Lock instanceWriteLock = instanceReadWriteLock.writeLock();

    private AppConfigurationEntry[] appConfigurationEntry;
    private Constructor<?>[] loginModuleConstructors;

    public JAASModulesManager(boolean returnNullContexts, ExtendedConfigFile jaasConfig, Map<String, ?> properties, String appContext) throws AuthException {
        super(returnNullContexts);

        this.jaasConfig = jaasConfig;
        this.appContext = appContext;

        initialize();
    }

    @Override
    public Map<String, Object> getInitProperties(int i, Map<String, ?> properties) {
        Map<String, Object> initProperties = new HashMap<>();

        if (appConfigurationEntry[i] != null) {
            if (properties != null && !properties.isEmpty()) {
                initProperties.putAll(properties);
            }

            @SuppressWarnings("unchecked")
            Map<String, Object> options = (Map<String, Object>) appConfigurationEntry[i].getOptions();
            if (options != null && !options.isEmpty()) {
                initProperties.putAll(options);
            }
        }

        return initProperties;
    }

    @Override
    public final void refresh() {
        jaasConfig.refresh();
        initialize();
    }

    /**
     * This implementation does not depend on authContextID
     *
     * @param <M> Type of the template
     * @param template the template used to create the module
     * @param authContextID (ignored by this context system)
     * @return true if has modules
     * @throws AuthException if something goes wrong
     */
    @Override
    public <M> boolean hasModules(M[] template, String authContextID) throws AuthException {
        loadConstructors(template, authContextID);

        for (Constructor<?> constructor : loginModuleConstructors) {
            if (constructor != null) {
                return true;
            }
        }

        return false;
    }

    /**
     * this implementation does not depend on authContextID
     *
     * @param <M> Type of the template
     * @param template template the template used to create the module
     * @param authContextID (ignored by this context system)
     * @return the modules
     * @throws AuthException if something goes wrong
     */
    @Override
    public <M> M[] getModules(M[] template, String authContextID) throws AuthException {
        loadConstructors(template, authContextID);

        List<M> moduleInstances = new ArrayList<>(loginModuleConstructors.length);

        for (int moduleNumber = 0; moduleNumber < loginModuleConstructors.length; moduleNumber++) {
            if (loginModuleConstructors[moduleNumber] == null) {
                moduleInstances.add(moduleNumber, null);
            } else {
                int j = moduleNumber;
                try {
                    moduleInstances.add(j, (M) loginModuleConstructors[j].newInstance(ARGS));
                } catch (ReflectiveOperationException | IllegalArgumentException e) {
                    throw (AuthException) new AuthException().initCause(e.getCause());
                }
            }
        }

        return moduleInstances.toArray(template);
    }

    @Override
    public boolean shouldStopProcessingModules(AuthStatus[] successValue, int moduleNumber, AuthStatus moduleStatus) {
        if (appConfigurationEntry[moduleNumber] != null && loginModuleConstructors[moduleNumber] != null) {
            LoginModuleControlFlag flag = appConfigurationEntry[moduleNumber].getControlFlag();

            if (REQUISITE.equals(flag)) {
                for (AuthStatus authStatus : successValue) {
                    if (moduleStatus == authStatus) {
                        return false;
                    }
                }

                return true;
            } else if (SUFFICIENT.equals(flag)) {
                for (AuthStatus authStatus : successValue) {
                    if (moduleStatus == authStatus) {
                        return true;
                    }
                }

                return false;
            }
        }

        return false;
    }

    @Override
    public AuthStatus getReturnStatus(AuthStatus[] successValue, AuthStatus defaultFailStatus, AuthStatus[] status, int position) {
        AuthStatus returnStatus = null;

        for (int moduleNumber = 0; moduleNumber <= position; moduleNumber++) {
            if (appConfigurationEntry[moduleNumber] != null && loginModuleConstructors[moduleNumber] != null) {

                LoginModuleControlFlag flag = appConfigurationEntry[moduleNumber].getControlFlag();

                LOG.log(DEBUG, "getReturnStatus - flag: {0}", flag);

                final AuthStatus moduleAuthStatus = status[moduleNumber];
                if (flag == REQUIRED || flag == REQUISITE) {
                    boolean isSuccessValue = false;
                    for (AuthStatus authStatus : successValue) {
                        if (authStatus == moduleAuthStatus) {
                            isSuccessValue = true;
                        }
                    }

                    if (isSuccessValue) {
                        if (returnStatus == null) {
                            returnStatus = moduleAuthStatus;
                        }
                        continue;
                    }

                    LOG.log(DEBUG, "ReturnStatus - REQUIRED or REQUISITE failure: {0}", moduleAuthStatus);
                    return moduleAuthStatus;
                } else if (flag == SUFFICIENT) {
                    if (shouldStopProcessingModules(successValue, moduleNumber, moduleAuthStatus)) {
                        LOG.log(DEBUG, "ReturnStatus - Sufficient success: {0}", moduleAuthStatus);
                        return moduleAuthStatus;
                    }

                } else if (flag == OPTIONAL) {
                    if (returnStatus == null) {
                        for (AuthStatus authStatus : successValue) {
                            if (moduleAuthStatus == authStatus) {
                                returnStatus = moduleAuthStatus;
                            }
                        }
                    }
                }
            }
        }

        if (returnStatus != null) {
            LOG.log(DEBUG, "ReturnStatus - result: {0}", returnStatus);
            return returnStatus;
        }

        LOG.log(DEBUG, "ReturnStatus - Default faiure status: {0}", defaultFailStatus);

        return defaultFailStatus;
    }



    // ### Private methods

    private void initialize() {
        boolean found = false;
        boolean foundDefault = false;
        instanceWriteLock.lock();
        try {
            appConfigurationEntry = jaasConfig.getAppConfigurationEntry(appContext);
            if (appConfigurationEntry == null) {

                // NEED TO MAKE SURE THIS LOOKUP only occurs when registered for *
                appConfigurationEntry = jaasConfig.getAppConfigurationEntry(DEFAULT_ENTRY_NAME);
                if (appConfigurationEntry == null) {
                    appConfigurationEntry = new AppConfigurationEntry[0];
                } else {
                    foundDefault = true;
                }
            } else {
                found = true;
            }
            loginModuleConstructors = null;
        } finally {
            instanceWriteLock.unlock();
        }

        if (!found) {
            if (!foundDefault) {
                LOG.log(INFO, "JAASModulesManager no entries matched appContext ({0}) or ({1})", appContext, DEFAULT_ENTRY_NAME);
            } else {
                LOG.log(INFO, "JAASModulesManager appContext ({0}) matched ({1})", appContext, DEFAULT_ENTRY_NAME);
            }
        }
    }


    private <M> void loadConstructors(M[] template, String authContextID) throws AuthException {
        if (loginModuleConstructors == null) {
            try {
                Class<?> moduleType = template.getClass().getComponentType();

                Constructor<?>[] loginModuleCtors = new Constructor[appConfigurationEntry.length];
                ClassLoader loader = Thread.currentThread().getContextClassLoader();

                for (int i = 0; i < appConfigurationEntry.length; i++) {
                    String loginModuleName = appConfigurationEntry[i].getLoginModuleName();
                    try {
                        Class<?> loginModuleClass = Class.forName(loginModuleName, true, loader);
                        if (moduleType.isAssignableFrom(loginModuleClass)) {
                            loginModuleCtors[i] = loginModuleClass.getConstructor(PARAMS);
                        }

                    } catch (Throwable t) {
                        LOG.log(WARNING, "Skipping unloadable class: {0} of appCOntext: {1}", loginModuleName, appContext);
                        LOG.log(TRACE, "Skipping unloadable class - cause.", t);
                    }
                }

                loginModuleConstructors = loginModuleCtors;

            } catch (Exception pae) {
                throw (AuthException) new AuthException().initCause(pae.getCause());
            }
        }
    }
}
