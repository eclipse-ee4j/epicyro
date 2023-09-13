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
 * This structure holds the configuration for an authentication module (SAM or CAM).
 *
 * <p>
 * As an example, in GlassFish this would be expressed by the <code>provider-config</code> element in domain.xml:
 *
 * <pre>
 *  &lt;provider-config provider-type="server" provider-id="GFConsoleAuthModule" class-name="org.glassfish.admingui.common.security.AdminConsoleAuthModule"&gt;
 *    &lt;request-policy auth-source="sender"&lt;/request-policy&gt;
 *    &lt;response-policy&gt;&lt;/response-policy&gt;
 *    &lt;property name="loginPage" value="/login.jsf"&gt;&lt;/property&gt;
 *    &lt;property name="loginErrorPage" value="/loginError.jsf"&lt;/property&gt;
 *  &lt;/provider-config&gt;
 * </pre>
 *
 */
public class AuthModuleConfig extends AuthModuleBaseConfig {

    private final String moduleType; // authentication moduleType (client, server, client-server)

    public AuthModuleConfig(String moduleType, String moduleClassName, MessagePolicy requestPolicy, MessagePolicy responsePolicy, Map<String, Object> options) {
        super(moduleClassName, requestPolicy, responsePolicy, options);
        this.moduleType = moduleType;
    }

    public String getType() {
        return moduleType;
    }
}