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

import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.smallrye.mutiny.Uni;
import io.undertow.security.api.SecurityContext;
import io.undertow.server.HttpServerExchange;
import io.undertow.servlet.handlers.ServletRequestContext;
import io.vertx.ext.web.RoutingContext;

import jakarta.inject.Singleton;
import jakarta.servlet.http.HttpServletResponse;

import java.util.HashMap;
import java.util.Map;

import static jakarta.servlet.http.HttpServletResponse.SC_FORBIDDEN;
import static org.glassfish.epicyro.quarkus.runtime.EpicyroAuthenticationMechanism.CONTAINER_REAUTHENTICATION;
import static org.glassfish.epicyro.quarkus.runtime.EpicyroAuthenticationMechanism.VALIDATED;

/**
 * Vert.x side of the extension.
 *
 * <p>
 * Authentication itself happens later, inside Undertow, so {@link #authenticate} leaves the request anonymous.
 * The challenge is needed for Quarkus REST: when {@code @RolesAllowed} rejects an anonymous caller, Quarkus REST maps
 * the {@code UnauthorizedException} itself by asking the Vert.x mechanisms for a challenge, and never lets it reach
 * Undertow. Here the servlet security context is asked to authenticate again with authentication required, which
 * calls the {@code ServerAuthModule} with {@code isMandatory=true}; its status and headers become the challenge.
 */
@Singleton
public class EpicyroHttpAuthenticationMechanism implements HttpAuthenticationMechanism {

    @Override
    public Uni<SecurityIdentity> authenticate(RoutingContext context, IdentityProviderManager identityProviderManager) {
        return Uni.createFrom().nullItem();
    }

    @Override
    public Uni<ChallengeData> getChallenge(RoutingContext context) {
        ServletRequestContext servletRequestContext = ServletRequestContext.current();
        if (servletRequestContext == null) {
            // Not a servlet request
            return Uni.createFrom().nullItem();
        }

        HttpServerExchange exchange = servletRequestContext.getExchange();
        if (exchange.getAttachment(VALIDATED) == null) {
            // No ServerAuthModule handled this request. Also prevents recursion via QuarkusAuthMechanism.sendChallenge.
            return Uni.createFrom().nullItem();
        }

        SecurityContext securityContext = exchange.getSecurityContext();
        securityContext.setAuthenticationRequired();
        boolean authenticated;
        exchange.putAttachment(CONTAINER_REAUTHENTICATION, true);

        try {
            authenticated = securityContext.authenticate();
        } finally {
            exchange.removeAttachment(CONTAINER_REAUTHENTICATION);
        }

        if (authenticated) {
            // Authenticated, but the caller still lacks the required role
            return Uni.createFrom().item(new ChallengeData(SC_FORBIDDEN));
        }

        HttpServletResponse response = (HttpServletResponse) servletRequestContext.getServletResponse();
        Map<CharSequence, String> headers = new HashMap<>();
        for (String name : response.getHeaderNames()) {
            headers.put(name, response.getHeader(name));
        }

        return Uni.createFrom().item(new ChallengeData(exchange.getStatusCode(), headers));
    }
}
