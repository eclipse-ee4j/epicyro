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

import io.undertow.server.HandlerWrapper;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.servlet.handlers.ServletRequestContext;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.jboss.logging.Logger;

import static io.undertow.servlet.handlers.ServletRequestContext.ATTACHMENT_KEY;
import static org.glassfish.epicyro.quarkus.runtime.EpicyroAuthenticationMechanism.VALIDATED;

/**
 * Calls {@code secureResponse} on the module after the request was handled, when {@code validateRequest} returned
 * SUCCESS for it.
 */
class SecureResponseHandlerWrapper implements HandlerWrapper {

    private static final Logger LOG = Logger.getLogger(SecureResponseHandlerWrapper.class);

    private final AuthenticationServiceHolder authenticationService;

    SecureResponseHandlerWrapper(AuthenticationServiceHolder authenticationService) {
        this.authenticationService = authenticationService;
    }

    @Override
    public HttpHandler wrap(HttpHandler next) {
        return new HttpHandler() {
            @Override
            public void handleRequest(HttpServerExchange exchange) throws Exception {
                next.handleRequest(exchange);

                if (exchange.getAttachment(VALIDATED) == null) {
                    return;
                }

                ServletRequestContext servletRequestContext = exchange.getAttachment(ATTACHMENT_KEY);
                HttpServletRequest request = (HttpServletRequest) servletRequestContext.getServletRequest();
                HttpServletResponse response = (HttpServletResponse) servletRequestContext.getServletResponse();

                if (request.isAsyncStarted()) {
                    // TODO: call secureResponse when the async request completes, before the response is committed
                    LOG.debugf("Not calling secureResponse for async request %s", request.getRequestURI());
                    return;
                }

                authenticationService.get().secureResponse(request, response);
            }
        };
    }
}
