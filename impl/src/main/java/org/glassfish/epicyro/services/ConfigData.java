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

package org.glassfish.epicyro.services;

import jakarta.security.auth.message.config.AuthConfig;
import jakarta.security.auth.message.config.AuthConfigProvider;
import jakarta.security.auth.message.config.ClientAuthConfig;
import jakarta.security.auth.message.config.ServerAuthConfig;

class ConfigData {

    private AuthConfigProvider provider;
    private AuthConfig serverConfig;
    private AuthConfig clientConfig;

    ConfigData() {
    }

    ConfigData(AuthConfigProvider authConfigProvider, AuthConfig authConfig) {
        provider = authConfigProvider;

        if (authConfig instanceof ServerAuthConfig) {
            serverConfig = authConfig;
        } else if (authConfig instanceof ClientAuthConfig) {
            clientConfig = authConfig;
        } else {
            throw new IllegalArgumentException();
        }
    }

    public AuthConfigProvider getProvider() {
        return provider;
    }

    public AuthConfig getServerConfig() {
        return serverConfig;
    }

    public AuthConfig getClientConfig() {
        return clientConfig;
    }
}