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

package org.omnifaces.eleos.config.factory;

import static java.util.Collections.emptySet;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

import org.omnifaces.eleos.data.AuthModulesLayerConfig;


/**
 * AuthConfigImpl relies on a ConfigParser to read
 * the module configuration.
 *
 * <p> The ConfigParser is expected to parse that information
 * into the HashMap described below.
 *
 * @version %I%, %G%
 */
public interface ConfigParser {

    /**
     * Initialize the parser.
     * Passing null as argument means the parser is to find
     * configuration object as necessary.
     */
    default void initialize(Object config) throws IOException {
        
    }

    /**
     * Get the module configuration information.
     * The information is returned as a Map.
     *
     * <p> The key is a layer:
     * <ul>
     *   <li>SOAP
     *   <li>HttpServlet
     * </ul>
     *
     * <p>The value is a AuthModulesLayerConfig, which contains:
     *
     * <ul>
     *   <li> default default Client Module Id 
     *   <li> default default Server Module Id 
     *   <li> Map, where
     *		    key	= auth module ID
     *		    value = AuthModuleConfig
     * </ul>
     *
     * <p> An AuthModuleConfig contains:
     *
     * <ul>
     *   <li> moduleType (client or server)
     *   <li> moduleClassName
     *   <li> default requestPolicy
     *   <li> default responsePolicy
     *   <li> options
     * </ul>
     */
    Map<String, AuthModulesLayerConfig> getAuthModuleLayers();

    /**
     * Get the layers for which a default provider should be created when the
     * parser is loaded.
     */
    default Set<String> getLayersWithDefault() {
        return emptySet();
    }
}
