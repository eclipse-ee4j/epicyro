/*
 * Copyright (c) 2019 OmniFaces. All rights reserved.
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

package org.omnifaces.eleos.services;

import static org.omnifaces.eleos.config.helper.HttpServletConstants.HTTPSERVLET;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;

import org.omnifaces.eleos.config.factory.ConfigParser;
import org.omnifaces.eleos.config.helper.AuthMessagePolicy;
import org.omnifaces.eleos.config.helper.ModuleConfigurationManager;
import org.omnifaces.eleos.config.module.configprovider.GFServerConfigProvider;

public class DefaultAuthenticationService extends BaseAuthenticationService {

    public DefaultAuthenticationService(String appContext, Map<String, Object> map, ConfigParser parser, CallbackHandler callbackHandler) {

        init(HTTPSERVLET, appContext, map, callbackHandler, null);
        
        ModuleConfigurationManager.init(parser, factory, new GFServerConfigProvider(factory));

        if (!hasExactMatchAuthProvider()) {
            setRegistrationId(
                factory.registerConfigProvider(
                    new GFServerConfigProvider(factory), 
                    HTTPSERVLET, appContext,
                    "Eleos provider: " + HTTPSERVLET + ":" + appContext));
        }

    }

    public CallbackHandler getCallbackHandler() {
        return AuthMessagePolicy.getDefaultCallbackHandler();
    }

}
