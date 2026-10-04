/*
 * Copyright (c) 2026 Contributors to the Eclipse Foundation.
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
package org.glassfish.epicyro.quarkus.runtime;

import jakarta.servlet.ServletContext;

import java.util.HashMap;
import java.util.Map;

import org.glassfish.epicyro.config.factory.BaseAuthConfigFactory;
import org.glassfish.epicyro.services.DefaultAuthenticationService;

import static org.glassfish.epicyro.config.helper.HttpServletConstants.POLICY_CONTEXT;

/**
 * Creates the application's {@link DefaultAuthenticationService} on first use, i.e. on the first request.
 *
 * <p>
 * The service obtains the {@code AuthConfigFactory} when it's created. Creating it lazily (as GlassFish does) means
 * it uses the factory that is installed once the application's ServletContainerInitializers and
 * ServletContextListeners have run, which may have replaced it via {@code AuthConfigFactory.setFactory}.
 */
class AuthenticationServiceHolder {

    private final ServletContext servletContext;

    private volatile DefaultAuthenticationService authenticationService;

    AuthenticationServiceHolder(ServletContext servletContext) {
        this.servletContext = servletContext;
    }

    DefaultAuthenticationService get() {
        DefaultAuthenticationService service = authenticationService;
        if (service == null) {
            synchronized (this) {
                service = authenticationService;
                if (service == null) {
                    String appContextId = BaseAuthConfigFactory.getAppContextID(servletContext);

                    // Passed to the AuthConfigProvider and modules. Jakarta Authentication requires the policy
                    // context key when Jakarta Authorization is supported (as GlassFish does). There is no Jakarta
                    // Authorization in Quarkus yet, so the application context ID stands in for its context ID.
                    // TODO: use the real policy context ID once Jakarta Authorization is supported
                    Map<String, Object> properties = new HashMap<>();
                    properties.put(POLICY_CONTEXT, appContextId);

                    service = new DefaultAuthenticationService(
                            appContextId,
                            properties,
                            null,
                            new QuarkusCallbackHandler());
                    authenticationService = service;
                }
            }
        }

        return service;
    }
}
