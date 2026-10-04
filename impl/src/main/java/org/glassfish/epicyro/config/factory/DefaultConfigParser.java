/*
 * Copyright (c) 2019, 2021 OmniFaces. All rights reserved.
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

package org.glassfish.epicyro.config.factory;

import static org.glassfish.epicyro.config.helper.HttpServletConstants.HTTPSERVLET;

import java.util.HashMap;
import java.util.Map;

import org.glassfish.epicyro.data.AuthModuleConfig;
import org.glassfish.epicyro.data.AuthModulesLayerConfig;

public class DefaultConfigParser implements ConfigParser {
    
    private final Map<String, AuthModulesLayerConfig> authModuleLayers = new HashMap<>();
    
    public DefaultConfigParser() {}
    
    public DefaultConfigParser(Class<?> authModuleClass) {
        withAuthModuleClass(authModuleClass);
    }
    
    public AuthModuleConfig withAuthModuleClass(Class<?> authModuleClass) {
        AuthModulesLayerConfig authModulesLayerConfig = new AuthModulesLayerConfig(authModuleClass);
        
        authModuleLayers.put(HTTPSERVLET, authModulesLayerConfig);
        
        return authModulesLayerConfig
                .getAuthModules()
                .get(authModuleClass.getSimpleName());
    }
    
    
    @Override
    public Map<String, AuthModulesLayerConfig> getAuthModuleLayers() {
        return authModuleLayers;
    }
    
}
