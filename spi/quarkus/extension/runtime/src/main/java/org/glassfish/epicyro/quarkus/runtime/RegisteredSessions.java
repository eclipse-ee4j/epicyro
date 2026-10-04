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

import io.undertow.security.idm.Account;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.session.Session;
import io.undertow.server.session.SessionListener;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.security.Principal;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.glassfish.epicyro.config.helper.Caller;

/**
 * The callers a {@code ServerAuthModule} asked to remember with {@code jakarta.servlet.http.registerSession}, per HTTP
 * session.
 *
 * <p>
 * Deliberately not stored as an HTTP session attribute: application code could then put a caller there at any time,
 * which the next request would pick up as the registered identity. Catalina (GlassFish) keeps it in an internal session
 * field; Undertow has no such field, so this keeps them per session ID, outside the session. Undertow's core session
 * listener (not visible to the application) keeps it in line with the session lifecycle.
 */
class RegisteredSessions implements SessionListener {

    private final Map<String, Caller> callers = new ConcurrentHashMap<>();

    Caller get(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session == null ? null : callers.get(session.getId());
    }

    void register(HttpServletRequest request, Caller caller) {
        callers.put(request.getSession(true).getId(), caller);
    }

    void remove(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            callers.remove(session.getId());
        }
    }

    @Override
    public void sessionDestroyed(Session session, HttpServerExchange exchange, SessionDestroyedReason reason) {
        callers.remove(session.getId());
    }

    @Override
    public void sessionIdChanged(Session session, String oldSessionId) {
        Caller caller = callers.remove(oldSessionId);
        if (caller != null) {
            callers.put(session.getId(), caller);
        }
    }

    /**
     * Shown to the module as {@code HttpServletRequest#getUserPrincipal()} while it validates a request of a session
     * with a registered caller. When the module passes this instance back in a {@code CallerPrincipalCallback}, the
     * registered caller is continued.
     */
    static final class RegisteredSessionPrincipal implements Principal {

        private final String name;

        RegisteredSessionPrincipal(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public String toString() {
            return name;
        }
    }

    /** Account for the marker principal, without roles; only exposed while the module validates the request. */
    static final class RegisteredSessionAccount implements Account {

        private static final long serialVersionUID = 1L;
        private final RegisteredSessionPrincipal principal;

        RegisteredSessionAccount(RegisteredSessionPrincipal principal) {
            this.principal = principal;
        }

        @Override
        public RegisteredSessionPrincipal getPrincipal() {
            return principal;
        }

        @Override
        public Set<String> getRoles() {
            return Set.of();
        }
    }
}
