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

package org.omnifaces.eleos.config.factory.file;

import static java.util.Arrays.asList;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.security.auth.message.config.AuthConfigFactory.RegistrationContext;

import org.omnifaces.eleos.config.factory.RegistrationContextImpl;

/**
 * Each entry is either a constructor entry or a registration entry. Use nulls rather than empty Strings or Lists for
 * fields that have no value.
 *
 *
 * @author Bobby Bissett
 */
public final class AuthConfigProviderEntry {

    /**
     * The class name of the AuthConfigProvider
     */
    private final String className;
    private final Map<String, String> properties;

    private List<RegistrationContext> registrationContexts;

    /*
     * This will create a constructor entry. The class must not be null. ONLY CONSTRUCTOR that should be used used to
     * construct defaultEntries (passed RegStoreFileParser construction). DO NOT USE OTHER CONSTRUCTORS to define
     * defaultEntries because they can create persisted registration entries which are not appropriate as defaultEntries.
     */
    public AuthConfigProviderEntry(Class<?> clazz) {
        this(clazz.getName(), null);
    }

    /*
     * This will create a constructor entry. The className must not be null. ONLY CONSTRUCTOR that should be used used to
     * construct defaultEntries (passed RegStoreFileParser construction). DO NOT USE OTHER CONSTRUCTORS to define
     * defaultEntries because they can create persisted registration entries which are not appropriate as defaultEntries.
     */
    public AuthConfigProviderEntry(String className) {
        this(className, null);
    }

    /*
     * This will create a constructor entry. The className must not be null. ONLY OTHER CONSTRUCTOR that should be used used
     * to construct defaultEntries (passed RegStoreFileParser construction). DO NOT USE OTHER CONSTRUCTORS to define
     * defaultEntries because they can create persisted registration entries which are not appropriate as defaultEntries.
     */
    public AuthConfigProviderEntry(String className, Map<String, String> properties) {
        if (className == null) {
            throw new IllegalArgumentException("Class name for registration entry cannot be null");
        }

        this.className = className;
        this.properties = properties;
    }

    /*
     * This will create a registration entry. The list of registration contexts must not be null or empty. Each registration
     * context will contain at least a non-null layer or appContextId.
     */
    AuthConfigProviderEntry(String className, Map<String, String> properties, List<RegistrationContext> registrationContexts) {
        if (registrationContexts == null || registrationContexts.isEmpty()) {
            throw new IllegalArgumentException("Registration entry must contain one or more registration contexts");
        }

        this.className = className;
        this.properties = properties;
        this.registrationContexts = registrationContexts;
    }

    /*
     * THIS METHOD MAY BE USED FOR CONSTRUCTOR OR REGISTRATION ENTRIES A helper method for creating a registration entry
     * with one registration context. If the context is null, this entry is a constructor entry.
     */
    AuthConfigProviderEntry(String className, Map<String, String> properties, RegistrationContext registrationContext) {
        this.className = className;
        this.properties = properties;

        if (registrationContext != null) {
            this.registrationContexts = asList(new RegistrationContextImpl(
                registrationContext.getMessageLayer(),
                registrationContext.getAppContext(),
                registrationContext.getDescription(),
                registrationContext.isPersistent()));
        }
    }

    AuthConfigProviderEntry(AuthConfigProviderEntry other) {
        this.className = other.className;
        this.properties = other.properties;

        if (other.registrationContexts != null) {
            this.registrationContexts = new ArrayList<RegistrationContext>(other.registrationContexts);
        }
    }

    public boolean isConstructorEntry() {
        return registrationContexts == null;
    }

    public String getClassName() {
        return className;
    }

    public Map<String, String> getProperties() {
        return properties;
    }

    public List<RegistrationContext> getRegistrationContexts() {
        return registrationContexts;
    }

    /*
     * Compares an entry info to this one. They are considered to match if: - they are both constructor or are both
     * registration entries - the classnames are equal or are both null - the property maps are equal or are both null If
     * the entry is a registration entry, registration contexts are not considered for our purposes. For instance, we may
     * want to get a certain registration entry in order to add a registration context to it.
     * @see com.sun.enterprise.security.jaspic.config.RegStoreFileParser
     */
    boolean matchConstructors(AuthConfigProviderEntry target) {
        if (target == null) {
            return false;
        }

        return (!(isConstructorEntry() ^ target.isConstructorEntry()) && matchStrings(className, target.getClassName())
                && matchMaps(properties, target.getProperties()));
    }

    /*
     * Utility method for comparing strings such that two null strings are considered "equal."
     */
    public static boolean matchStrings(String s1, String s2) {
        if (s1 == null && s2 == null) {
            return true;
        }

        if (s1 == null || s2 == null) {
            return false;
        }

        return s1.equals(s2);
    }

    /*
     * Utility method for comparing maps such that two null maps are considered "equal."
     */
    static boolean matchMaps(Map<String, String> map1, Map<String, String> map2) {
        if (map1 == null && map2 == null) {
            return true;
        }

        if (map1 == null || map2 == null) {
            return false;
        }

        return map1.equals(map2);
    }

}
