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

import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.undertow.runtime.QuarkusUndertowAccount;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.SecurityContext;
import io.undertow.server.HttpServerExchange;
import io.undertow.servlet.handlers.ServletRequestContext;
import io.undertow.util.AttachmentKey;
import io.undertow.vertx.VertxHttpExchange;
import io.vertx.ext.web.RoutingContext;

import jakarta.security.auth.message.AuthException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.UncheckedIOException;

import org.glassfish.epicyro.config.helper.Caller;
import org.glassfish.epicyro.quarkus.runtime.RegisteredSessions.RegisteredSessionAccount;
import org.glassfish.epicyro.quarkus.runtime.RegisteredSessions.RegisteredSessionPrincipal;
import org.glassfish.epicyro.services.ValidationOutcome;

import static io.undertow.security.api.AuthenticationMechanism.AuthenticationMechanismOutcome.AUTHENTICATED;
import static io.undertow.security.api.AuthenticationMechanism.AuthenticationMechanismOutcome.NOT_ATTEMPTED;
import static io.undertow.security.api.AuthenticationMechanism.AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
import static jakarta.security.auth.message.AuthStatus.SUCCESS;

/**
 * Undertow authentication mechanism that calls the registered {@code ServerAuthModule} through Epicyro.
 *
 * <p>
 * When no module is registered for the application, it delegates to Quarkus' own mechanism, so the application
 * behaves exactly as without this extension.
 */
public class EpicyroAuthenticationMechanism implements AuthenticationMechanism {

    /** Set when the module returned SUCCESS, so secureResponse must be called after the request. */
    static final AttachmentKey<Boolean> VALIDATED = AttachmentKey.create(Boolean.class);

    /** Set when the module did not return SUCCESS and has written the response (challenge, redirect, error). */
    static final AttachmentKey<Boolean> RESPONSE_HANDLED = AttachmentKey.create(Boolean.class);

    /** Set once the request has been authenticated by the security chain at its start. */
    static final AttachmentKey<Boolean> AUTHENTICATED_ONCE = AttachmentKey.create(Boolean.class);

    /**
     * Set while the container itself runs authentication again (Quarkus' exception handler after an
     * UnauthorizedException, the Vert.x challenge). Undertow's {@code HttpServletRequest#authenticate()} does exactly
     * the same, so this is how the two are told apart.
     */
    static final AttachmentKey<Boolean> CONTAINER_REAUTHENTICATION = AttachmentKey.create(Boolean.class);

    /** Set while the module's validateRequest runs. */
    static final AttachmentKey<Boolean> IN_VALIDATE_REQUEST = AttachmentKey.create(Boolean.class);

    static final String AUTH_TYPE = "JAKARTA_AUTHENTICATION";

    private final AuthenticationServiceHolder authenticationService;
    private final RegisteredSessions registeredSessions;
    private final AuthenticationMechanism delegate;

    EpicyroAuthenticationMechanism(AuthenticationServiceHolder authenticationService, RegisteredSessions registeredSessions, AuthenticationMechanism delegate) {
        this.authenticationService = authenticationService;
        this.registeredSessions = registeredSessions;
        this.delegate = delegate;
    }

    @Override
    public AuthenticationMechanismOutcome authenticate(HttpServerExchange exchange, SecurityContext securityContext) {
        if (!isServerAuthModuleRegistered()) {
            return delegate.authenticate(exchange, securityContext);
        }

        if (exchange.getAttachment(IN_VALIDATE_REQUEST) != null) {
            // The module called HttpServletRequest#authenticate() from its own validateRequest. The spec requires the
            // container not to call validateRequest again, but to do what it does without an AuthConfigProvider.
            return delegate.authenticate(exchange, securityContext);
        }

        // A later run that the container didn't start itself comes from HttpServletRequest#authenticate()
        boolean calledFromAuthenticate =
            exchange.getAttachment(AUTHENTICATED_ONCE) != null &&
            exchange.getAttachment(CONTAINER_REAUTHENTICATION) == null;


        exchange.putAttachment(AUTHENTICATED_ONCE, true);

        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        HttpServletRequest request = (HttpServletRequest) servletRequestContext.getServletRequest();
        HttpServletResponse response = (HttpServletResponse) servletRequestContext.getServletResponse();

        // A caller registered earlier in this session (jakarta.servlet.http.registerSession) is shown to the module as
        // a marker principal, which the module can pass back to continue it
        Caller registeredCaller = registeredSessions.get(request);
        RegisteredSessionPrincipal registeredPrincipal = null;
        EpicyroSecurityContext epicyroSecurityContext = securityContext instanceof EpicyroSecurityContext context
                ? context
                : null;

        if (registeredCaller != null && epicyroSecurityContext != null) {
            registeredPrincipal = new RegisteredSessionPrincipal(registeredCaller.getName());
            epicyroSecurityContext.setRegisteredSessionAccount(new RegisteredSessionAccount(registeredPrincipal));
        }

        ValidationOutcome validationOutcome;
        Caller caller;
        exchange.putAttachment(IN_VALIDATE_REQUEST, true);
        try {
            validationOutcome =
                authenticationService
                    .get()
                    .validateRequest(
                        request,
                        response, calledFromAuthenticate,
                        securityContext.isAuthenticationRequired());

            caller = validationOutcome.caller();

        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } finally {
            exchange.removeAttachment(IN_VALIDATE_REQUEST);
            if (epicyroSecurityContext != null) {
                epicyroSecurityContext.setRegisteredSessionAccount(null);
            }
        }

        if (isContinueSession(caller, registeredPrincipal)) {
            // The module continues the registered session: restore the caller the container stored, with its original
            // principal (possibly a custom one) and groups
            caller = registeredCaller;
        } else if (isRegisterSession(caller, request, response)) {
            registeredSessions.register(request, caller);
        }

        if (!SUCCESS.equals(validationOutcome.authStatus())) {
            // SEND_CONTINUE, SEND_FAILURE (or SEND_SUCCESS): the module already wrote the response
            exchange.putAttachment(RESPONSE_HANDLED, true);
            return NOT_AUTHENTICATED;
        }

        exchange.putAttachment(VALIDATED, true);
        applyWrappers(servletRequestContext, request, response);

        if (caller == null || caller.getName() == null) {
            // SUCCESS without a caller principal: continue anonymously (the "do nothing" protocol)
            return NOT_ATTEMPTED;
        }

        SecurityIdentity identity = QuarkusSecurityIdentity.builder()
                .setPrincipal(caller.getCallerPrincipal())
                .addRoles(caller.getGroups())
                .setAnonymous(false)
                .build();

        // Quarkus resolves the identity from the Vert.x routing context first, so it has to be set there as well.
        // authenticationComplete then notifies the receiver Quarkus registered, which updates CurrentIdentityAssociation.
        QuarkusHttpUser.setIdentity(identity, getRoutingContext(exchange));
        securityContext.authenticationComplete(new QuarkusUndertowAccount(identity), AUTH_TYPE, false);

        return AUTHENTICATED;
    }

    @Override
    public ChallengeResult sendChallenge(HttpServerExchange exchange, SecurityContext securityContext) {
        if (exchange.getAttachment(RESPONSE_HANDLED) != null) {
            // No status code: the module already set it, and the response may already be committed, in which case
            // Undertow setting it again fails with "Response head already sent"
            return new ChallengeResult(true);
        }

        if (!isServerAuthModuleRegistered()) {
            // QuarkusAuthMechanism writes and ends the response itself, but still returns the status code, which
            // Undertow then fails to set on the already sent response. Only pass on whether a challenge was sent.
            return new ChallengeResult(delegate.sendChallenge(exchange, securityContext).isChallengeSent());
        }

        // The module returned SUCCESS without authenticating while authentication was required: Undertow sends a 403
        return ChallengeResult.NOT_SENT;
    }

    private boolean isContinueSession(Caller caller, RegisteredSessionPrincipal registeredPrincipal) {
        return
            caller != null && registeredPrincipal != null && caller.getCallerPrincipal() == registeredPrincipal;
    }

    private boolean isRegisterSession(Caller caller, HttpServletRequest request, HttpServletResponse response) {
        return
            caller != null && caller.getName() != null &&
            authenticationService.get().mustRegisterSession(request, response);
    }

    private boolean isServerAuthModuleRegistered() {
        try {
            return authenticationService.get().getServerAuthConfig() != null;
        } catch (AuthException e) {
            throw new IllegalStateException(e);
        }
    }

    private void applyWrappers(ServletRequestContext servletRequestContext, HttpServletRequest request, HttpServletResponse response) {
        HttpServletRequest wrappedRequest = authenticationService.get().getWrappedRequestIfSet(request, response);
        if (wrappedRequest != request) {
            servletRequestContext.setServletRequest(wrappedRequest);
        }

        HttpServletResponse wrappedResponse = authenticationService.get().getWrappedResponseIfSet(request, response);
        if (wrappedResponse != response) {
            servletRequestContext.setServletResponse(wrappedResponse);
        }
    }

    private static RoutingContext getRoutingContext(HttpServerExchange exchange) {
        return (RoutingContext) ((VertxHttpExchange) exchange.getDelegate()).getContext();
    }
}
