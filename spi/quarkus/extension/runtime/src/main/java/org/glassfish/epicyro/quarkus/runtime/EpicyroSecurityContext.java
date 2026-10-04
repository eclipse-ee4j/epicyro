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

import io.quarkus.arc.Arc;
import io.quarkus.arc.InstanceHandle;
import io.quarkus.security.identity.CurrentIdentityAssociation;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AnonymousAuthenticationRequest;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.AuthenticationMode;
import io.undertow.security.api.SecurityContextFactory;
import io.undertow.security.idm.Account;
import io.undertow.security.idm.IdentityManager;
import io.undertow.security.impl.SecurityContextImpl;
import io.undertow.server.HttpServerExchange;
import io.undertow.servlet.handlers.ServletRequestContext;
import io.undertow.vertx.VertxHttpExchange;
import io.vertx.ext.web.RoutingContext;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import javax.security.auth.Subject;

import static io.undertow.security.api.AuthenticationMechanism.AuthenticationMechanismOutcome.AUTHENTICATED;
import static org.glassfish.epicyro.quarkus.runtime.EpicyroAuthenticationMechanism.AUTHENTICATED_ONCE;
import static org.glassfish.epicyro.quarkus.runtime.EpicyroAuthenticationMechanism.CONTAINER_REAUTHENTICATION;
import static org.glassfish.epicyro.quarkus.runtime.EpicyroAuthenticationMechanism.IN_VALIDATE_REQUEST;

/**
 * Undertow security context that implements {@code HttpServletRequest#logout()} and {@code authenticate()} for Jakarta
 * Authentication, and exposes a registered session's principal to the module.
 *
 * <p>
 * Undertow's {@code HttpServletRequest#logout()} ends up in {@link #logout()}, whether or not the caller is
 * authenticated. As GlassFish and Piranha do, the module's {@code cleanSubject} is called first, so it can clean up its
 * own mechanism state (cookies, tokens, provider sessions). Then the container clears its own state: the Undertow
 * account, and the Quarkus identity, which Undertow doesn't know about.
 */
class EpicyroSecurityContext extends SecurityContextImpl {

    /** Guards against a module calling {@code HttpServletRequest#logout()} from {@code cleanSubject}. */
    private static final ThreadLocal<Boolean> CLEANING_SUBJECT = new ThreadLocal<>();

    private final HttpServerExchange exchange;
    private final AuthenticationServiceHolder authenticationService;
    private final RegisteredSessions registeredSessions;
    private final AuthenticationMechanism authenticationMechanism;

    /** The registered session's marker account, exposed only while the module validates the request. */
    private Account registeredSessionAccount;

    EpicyroSecurityContext(HttpServerExchange exchange, AuthenticationMode authenticationMode,
            IdentityManager identityManager, AuthenticationServiceHolder authenticationService,
            RegisteredSessions registeredSessions, AuthenticationMechanism authenticationMechanism) {
        super(exchange, authenticationMode, identityManager);
        this.exchange = exchange;
        this.authenticationService = authenticationService;
        this.registeredSessions = registeredSessions;
        this.authenticationMechanism = authenticationMechanism;
    }

    static SecurityContextFactory factory(AuthenticationServiceHolder authenticationService,
            RegisteredSessions registeredSessions, AuthenticationMechanism authenticationMechanism) {
        return (exchange, mode, identityManager, programmaticMechName) -> {

            // Same as Undertow's default SecurityContextFactoryImpl, but creating this class
            EpicyroSecurityContext securityContext =
                new EpicyroSecurityContext(
                    exchange, mode, identityManager,
                    authenticationService, registeredSessions, authenticationMechanism);

            if (programmaticMechName != null) {
                securityContext.setProgramaticMechName(programmaticMechName);
            }

            return securityContext;
        };
    }

    /**
     * Undertow's {@code HttpServletRequest#getUserPrincipal()} returns the principal of this account. While the module
     * validates a request of a session with a registered caller, that is the marker principal, as GlassFish and
     * Piranha also make the registered principal available to the module before it validates the request.
     */
    @Override
    public Account getAuthenticatedAccount() {
        Account account = super.getAuthenticatedAccount();
        return account == null ? registeredSessionAccount : account;
    }

    void setRegisteredSessionAccount(Account registeredSessionAccount) {
        this.registeredSessionAccount = registeredSessionAccount;
    }

    /**
     * Undertow's {@code HttpServletRequest#authenticate()} returns true without calling any mechanism when the caller
     * is already authenticated. Jakarta Authentication requires {@code authenticate} to call {@code validateRequest}
     * (as GlassFish does), so in that case the module is called here.
     */
    @Override
    public boolean authenticate() {
        if (isAuthenticated() && isAuthenticateCall() && isServerAuthModuleRegistered()) {
            return reauthenticate();
        }

        return super.authenticate();
    }

    /** Called by HttpServletRequest#authenticate(), not at the start of the request or by the container itself. */
    private boolean isAuthenticateCall() {
        return
            exchange.getAttachment(AUTHENTICATED_ONCE) != null &&
            exchange.getAttachment(CONTAINER_REAUTHENTICATION) == null &&
            exchange.getAttachment(IN_VALIDATE_REQUEST) == null;
    }

    private boolean reauthenticate() {
        if (authenticationMechanism.authenticate(exchange, this) == AUTHENTICATED) {
            // The mechanism completed the authentication with the (possibly new) identity
            return true;
        }

        // The module didn't authenticate: like GlassFish, the previous identity no longer applies to this request
        super.logout();
        clearQuarkusIdentity();
        return false;
    }

    @Override
    public void logout() {
        if (CLEANING_SUBJECT.get() == null && isServerAuthModuleRegistered()) {
            CLEANING_SUBJECT.set(true);
            try {
                cleanSubject();
            } finally {
                CLEANING_SUBJECT.remove();
            }
        }

        super.logout();
        clearQuarkusIdentity();

        // As GlassFish's authenticator does: the session no longer carries the registered identity
        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        if (servletRequestContext != null) {
            registeredSessions.remove((HttpServletRequest) servletRequestContext.getServletRequest());
        }
    }

    private void cleanSubject() {
        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        if (servletRequestContext == null) {
            return;
        }

        // The Subject only carries the identity to the module; what matters is that the module gets the chance to
        // clean up. Like GlassFish, pass the current caller, or an empty Subject when not authenticated.
        Subject subject = new Subject();
        Account account = getAuthenticatedAccount();
        if (account != null && account.getPrincipal() != null) {
            subject.getPrincipals().add(account.getPrincipal());
        }

        authenticationService.get().clearSubject(
                (HttpServletRequest) servletRequestContext.getServletRequest(),
                (HttpServletResponse) servletRequestContext.getServletResponse(),
                subject);
    }

    private boolean isServerAuthModuleRegistered() {
        try {
            return authenticationService.get().getServerAuthConfig() != null;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Quarkus resolves the identity from the Vert.x routing context and CurrentIdentityAssociation, which Undertow's
     * logout doesn't touch. Replace it there with the anonymous identity.
     */
    private void clearQuarkusIdentity() {
        try (InstanceHandle<IdentityProviderManager> identityProviderManager = Arc.container().instance(IdentityProviderManager.class)) {
            if (!identityProviderManager.isAvailable()) {
                return;
            }

            SecurityIdentity anonymous =
                identityProviderManager
                    .get()
                    .authenticateBlocking(AnonymousAuthenticationRequest.INSTANCE);

            if (exchange.getDelegate() instanceof VertxHttpExchange vertxHttpExchange && vertxHttpExchange.getContext() instanceof RoutingContext routingContext) {
                QuarkusHttpUser.setIdentity(anonymous, routingContext);
            }

            try (InstanceHandle<CurrentIdentityAssociation> identityAssociation = Arc.container().instance(CurrentIdentityAssociation.class)) {
                if (identityAssociation.isAvailable()) {
                    identityAssociation.get().setIdentity(anonymous);
                }
            }
        }
    }
}
