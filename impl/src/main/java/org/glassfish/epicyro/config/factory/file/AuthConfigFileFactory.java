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

package org.glassfish.epicyro.config.factory.file;

import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import org.glassfish.epicyro.config.factory.BaseAuthConfigFactory;

/**
 *
 * @author ronmonzillo
 */
public class AuthConfigFileFactory extends BaseAuthConfigFactory {

    /**
     * The name of the Security property used to define the default providers used by the default AuthConfigFactory implementation class.
     */
    public static final String DEFAULT_FACTORY_DEFAULT_PROVIDERS = "authconfigprovider.factory.providers";

    // MUST "hide" regStore in derived class.
    private static volatile RegStoreFileParser regStore;

    /**
     * To specialize the defaultEntries passed to the {@link RegStoreFileParser} constructor, create another subclass of
     * BaseAuthconfigFactory, that is basically a copy of this class, with a change to the third argument of the call to new
     * ResSToreFileParser. To ensure runtime use of the the associated regStore, make sure that the new subclass also
     * contains an implementation of the getRegStore method.
     *
     * <p>
     * All EntyInfo OBJECTS PASSED as default Entries MUST HAVE BEEN CONSTRUCTED USING THE FOLLOWING CONSTRUCTOR:
     *
     * <pre>
     * <code>
     * AuthConfigProviderEntry(String className);
     * </code>
     * </pre>
     *
     * or
     *
     * <pre>
     * <code>
     * AuthConfigProviderEntry(String className, Map&lt;String, String&gt; properties);
     * </code>
     * </pre>
     *
     */
    public AuthConfigFileFactory() {
        if (doReadLocked(() -> regStore != null)) {
            return;
        }

        String userDir = System.getProperty("user.dir");
        String defaultProviderString = Security.getProperty(DEFAULT_FACTORY_DEFAULT_PROVIDERS);

        doWriteLocked(() -> {
            if (regStore == null) {
                regStore = new RegStoreFileParser(userDir, CONF_FILE_NAME, getDefaultProviders(defaultProviderString));
                _loadFactory();
            }
        });
    }

    @Override
    protected RegStoreFileParser getRegStore() {
        return doReadLocked(() -> regStore);
    }

    private List<AuthConfigProviderEntry> getDefaultProviders(String defaultProviderString) {
        if (defaultProviderString == null) {
            return null;
        }

        List<AuthConfigProviderEntry> defaultProviders = new ArrayList<>();
        for (String defaultProviderClassName : defaultProviderString.split(" ")) {
            defaultProviders.add(new AuthConfigProviderEntry(defaultProviderClassName));
        }

        return defaultProviders;
    }
}
