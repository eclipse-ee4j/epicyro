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

import org.omnifaces.eleos.config.factory.BaseAuthConfigFactory;

/**
 *
 * @author ronmonzillo
 */
public class AuthConfigFileFactory extends BaseAuthConfigFactory {

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
     * EntryInfo(String className, Map&lt;String, String&gt; properties);
     * </code>
     * </pre>
     *
     */
    public AuthConfigFileFactory() {
        if (doReadLocked(() -> regStore != null)) {
            return;
        }

        String userDir = System.getProperty("user.dir");

        doWriteLocked(() -> {
            if (regStore == null) {
                regStore = new RegStoreFileParser(userDir, CONF_FILE_NAME, null);
                _loadFactory();
            }
        });
    }

    @Override
    protected RegStoreFileParser getRegStore() {
        return doReadLocked(() -> regStore);
    }
}
