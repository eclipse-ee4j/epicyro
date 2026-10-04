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

package org.glassfish.epicyro.data;

import java.util.Map;

import jakarta.security.auth.message.MessagePolicy;


/**
 * This structure encapsulates a single authentication module and its related information.
 * 
 * @author Arjan Tijms (refactoring)
 */
public class AuthModuleBaseConfig {

    private final String moduleClassName;
    private final MessagePolicy requestPolicy;
    private final MessagePolicy responsePolicy;
    private final Map<String, Object> options;

    /**
     * Construct a AuthModuleBaseConfig
     *
     * <p>
     * An AuthModuleBaseConfig encapsulates a single module and its related information.
     *
     * @param moduleClassName the module class name
     * @param requestPolicy the request policy assigned to the module listed in this entry, which may be null.
     *
     * @param responsePolicy the response policy assigned to the module listed in this entry, which may be null.
     *
     * @param options the options configured for this module.
     */
    public AuthModuleBaseConfig(String moduleClassName, MessagePolicy requestPolicy, MessagePolicy responsePolicy, Map<String, Object> options) {
        this.moduleClassName = moduleClassName;
        this.requestPolicy = requestPolicy;
        this.responsePolicy = responsePolicy;
        this.options = options;
    }

    /**
     * Return the request policy assigned to this module.
     *
     * @return the policy, which may be null.
     */
    public MessagePolicy getRequestPolicy() {
        return requestPolicy;
    }

    /**
     * Return the response policy assigned to this module.
     *
     * @return the policy, which may be null.
     */
    public MessagePolicy getResponsePolicy() {
        return responsePolicy;
    }

    public String getModuleClassName() {
        return moduleClassName;
    }

    public Map<String, Object> getOptions() {
        return options;
    }


}