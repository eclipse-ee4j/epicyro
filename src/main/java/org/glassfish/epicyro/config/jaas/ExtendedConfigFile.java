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

package org.glassfish.epicyro.config.jaas;

import com.sun.security.auth.login.ConfigFile;

import java.lang.System.Logger;
import java.lang.reflect.Field;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Set;

import javax.security.auth.login.AppConfigurationEntry;

import static java.lang.System.Logger.Level.WARNING;
import static java.util.Collections.emptyMap;
import static javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag.REQUIRED;

/**
 *
 * @author Ron Monzillo
 */
public class ExtendedConfigFile extends ConfigFile {

    private static final Logger LOG = System.getLogger(ExtendedConfigFile.class.getName());

    // may be more than one delegate for a given jaas config file
    private Class<?> moduleClass;

    public static ExtendedConfigFile fromFileName(String configFileName) {
        if (configFileName == null) {
            return new ExtendedConfigFile();
        }

        try {
            return new ExtendedConfigFile(new URI(configFileName));
        } catch (URISyntaxException use) {
            throw new IllegalArgumentException(use);
        }

    }

    public ExtendedConfigFile() {
    }

    public ExtendedConfigFile(URI uri) {
        super(uri);
    }

    public ExtendedConfigFile(Class<?> moduleClass) {
        this.moduleClass = moduleClass;
    }

    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry(String applicationName) {
        if (moduleClass == null) {
            return super.getAppConfigurationEntry(applicationName);
        }

        AppConfigurationEntry appConfigurationEntry = new AppConfigurationEntry(
                moduleClass.getName(),
                REQUIRED,
                emptyMap());

        return new AppConfigurationEntry[] {appConfigurationEntry};
    }

    /**
     * The ExtendedConfigFile subclass was created because the Configuration interface does not provide a way to do what
     * this method does; i.e. get all the app names from the config.
     *
     * @param authModuleClass an Array of Class objects or null. When this parameter is not null, the appnames are filtered
     * by removing all names that are not associated via an AppConfigurationEntry with at least one LoginModule that
     * implements an authModuleClass.
     * @return String[] containing all the AppNames appearing in the config file.
     * @throws SecurityException if no reflective access
     */
    public String[] getAppNames(final Class[] authModuleClass) {

        final Set<String> nameSet;
        try {
            nameSet = (Set<String>) AccessController.doPrivileged(new PrivilegedExceptionAction() {

                @Override
                public Object run() throws Exception {
                    HashMap map;
                    Field field = ConfigFile.class.getDeclaredField("configuration");
                    field.setAccessible(true);
                    map = (HashMap) field.get(ExtendedConfigFile.this);
                    return map.keySet();
                }
            });

        } catch (PrivilegedActionException pae) {
            throw new SecurityException(pae.getCause());
        }

        // remove any modules that don't implement specified interface
        if (authModuleClass != null) {
            try {
                AccessController.doPrivileged(new PrivilegedExceptionAction() {

                    @Override
                    public Object run() throws Exception {
                        ClassLoader loader = Thread.currentThread().getContextClassLoader();
                        String[] names = nameSet.toArray(new String[nameSet.size()]);
                        for (String id : names) {
                            boolean hasAuthModule = false;
                            AppConfigurationEntry[] entry = getAppConfigurationEntry(id);
                            for (int i = 0; i < entry.length && !hasAuthModule; i++) {
                                String clazz = entry[i].getLoginModuleName();
                                try {
                                    Class c = Class.forName(clazz, true, loader);
                                    for (Class required : authModuleClass) {
                                        if (required.isAssignableFrom(c)) {
                                            hasAuthModule = true;
                                            break;
                                        }
                                    }
                                } catch (Throwable t) {
                                    LOG.log(WARNING, () -> "Skipping unloadable class: " + clazz + " of entry: " + id, t);
                                }
                            }
                            if (!hasAuthModule) {
                                nameSet.remove(id);
                            }
                        }
                        return null;
                    }
                });
            } catch (java.security.PrivilegedActionException pae) {
                throw new SecurityException(pae.getCause());
            }

        }
        return nameSet.toArray(new String[nameSet.size()]);
    }
}
