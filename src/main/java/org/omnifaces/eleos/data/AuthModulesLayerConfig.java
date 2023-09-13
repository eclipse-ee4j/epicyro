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

package org.omnifaces.eleos.data;

import java.util.HashMap;
import java.util.Map;

/**
 * This structure holds the authentication configuration for a given Jakarta Authentication layer.
 * 
 * <p>
 * There are currently two layers defined; HttpServlet and SOAP
 * 
 * <p>
 * For each layer, a number of authentication modules and their properties are defined.
 * 
 * @author Arjan Tijms (refactored)
 *
 */
public class AuthModulesLayerConfig {

    private String defaultClientModuleId;
    private String defaultServerModuleId;
    private Map<String, AuthModuleConfig> authModules; // key is auth module Id
    
    public AuthModulesLayerConfig(Class<?> moduleClass) {
       authModules = new HashMap<>();
       authModules.put(moduleClass.getSimpleName(), new AuthModuleConfig("server", moduleClass.getName(), null, null, null));
    }

    public AuthModulesLayerConfig(String defaultClientModuleId, String defaultServerModuleId, Map<String, AuthModuleConfig> authModules) {
        this.defaultClientModuleId = defaultClientModuleId;
        this.defaultServerModuleId = defaultServerModuleId;
        this.authModules = authModules;
    }

    public String getDefaultClientModuleId() {
        return defaultClientModuleId;
    }

    public String getDefaultServerModuleId() {
        return defaultServerModuleId;
    }

    public Map<String, AuthModuleConfig> getAuthModules() {
        return authModules;
    }

    public void setIdMap(Map<String, AuthModuleConfig> map) {
        authModules = map;
    }
}