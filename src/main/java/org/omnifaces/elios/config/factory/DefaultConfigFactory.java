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

package org.omnifaces.elios.config.factory;

import java.util.ArrayList;
import java.util.List;

import org.omnifaces.elios.config.factory.file.AuthConfigProviderEntry;
import org.omnifaces.elios.config.factory.file.RegStoreFileParser;
import org.omnifaces.elios.config.module.configprovider.GFServerConfigProvider;
import org.omnifaces.elios.services.WebServicesDelegate;

/**
 * This class implements methods in the abstract class AuthConfigFactory.
 * 
 * @author Shing Wai Chan
 */
public class DefaultConfigFactory extends BaseAuthConfigFactory {

    // MUST "hide" regStore in derived class.
    static RegStoreFileParser regStore = null;

    /**
     * to specialize the defaultEntries passed to the RegStoreFileParser constructor, create another subclass of
     * BaseAuthconfigFactory, that is basically a copy of this class, with a change to the third argument of the call to new
     * ResSToreFileParser. to ensure runtime use of the the associated regStore, make sure that the new subclass also
     * contains an implementation of the getRegStore method. As done within this class, use the locks defined in
     * BaseAuthConfigFactory to serialize access to the regStore (both within the class constructor, and within getRegStore)
     *
     * All EentyInfo OBJECTS PASSED as deualtEntries MUST HAVE BEEN CONSTRCTED USING THE FOLLOWING CONSTRUCTOR:
     *
     * EntryInfo(String className, Map<String, String> properties);
     *
     */
    public DefaultConfigFactory() {
        rLock.lock();
        try {
            if (regStore != null) {
                return;
            }
        } finally {
            rLock.unlock();
        }
        String userDir = System.getProperty("user.dir");
        wLock.lock();
        try {
            if (regStore == null) {
                initializeRegStore(userDir);
                _loadFactory();
            }
        } finally {
            wLock.unlock();
        }
    }

    /**
     * @param userDir
     */
    private static void initializeRegStore(String userDir) {
        regStore = new RegStoreFileParser(userDir, BaseAuthConfigFactory.CONF_FILE_NAME, getDefaultProviders());
    }

    @Override
    protected RegStoreFileParser getRegStore() {
        rLock.lock();
        try {
            return regStore;
        } finally {
            rLock.unlock();
        }
    }

    /*
     * Contains the default providers used when none are configured in a factory configuration file.
     */
    static List<AuthConfigProviderEntry> getDefaultProviders() {
        WebServicesDelegate delegate = null;
        
        if (delegate != null) {
            List<AuthConfigProviderEntry> entries = new ArrayList<AuthConfigProviderEntry>(2);
            entries.add(new AuthConfigProviderEntry(delegate.getDefaultWebServicesProvider(), null));
            entries.add(new AuthConfigProviderEntry(GFServerConfigProvider.class.getName(), null));
            return entries;
        }
        List<AuthConfigProviderEntry> entries = new ArrayList<AuthConfigProviderEntry>(1);
        entries.add(new AuthConfigProviderEntry(GFServerConfigProvider.class.getName(), null));
        return entries;
    }

}
