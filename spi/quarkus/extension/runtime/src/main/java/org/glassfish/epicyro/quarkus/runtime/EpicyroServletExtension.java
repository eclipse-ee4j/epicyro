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

import io.quarkus.undertow.runtime.QuarkusAuthMechanism;
import io.undertow.servlet.ServletExtension;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.ExceptionHandler;

import jakarta.security.auth.message.config.AuthConfigFactory;
import jakarta.servlet.ServletContext;

import org.glassfish.epicyro.config.factory.DefaultConfigFactory;

import static io.undertow.security.api.AuthenticationMode.PRO_ACTIVE;
import static org.glassfish.epicyro.quarkus.runtime.EpicyroAuthenticationMechanism.CONTAINER_REAUTHENTICATION;

/**
 * Installs Jakarta Authentication (Servlet Container Profile) into the Undertow deployment.
 *
 * <p>
 * Undertow has a dedicated slot for a Jakarta Authentication mechanism: when set, it is the <em>only</em> mechanism
 * in the security chain, which runs inside the servlet deployment where the real {@code HttpServletRequest} exists.
 * Constraint evaluation happens before it, and it runs again with authentication required when a secured resource
 * (e.g. {@code @RolesAllowed}) rejects an anonymous caller.
 */
public class EpicyroServletExtension implements ServletExtension {

    /** From {@link EpicyroConfig#virtualServerName()}; null keeps Undertow's default. */
    private String virtualServerName;

    public String getVirtualServerName() {
        return virtualServerName;
    }

    public void setVirtualServerName(String virtualServerName) {
        this.virtualServerName = virtualServerName;
    }

    @Override
    public void handleDeployment(DeploymentInfo deploymentInfo, ServletContext servletContext) {
        // Part of the application context ID, so set it before anything registers or looks up a provider
        if (virtualServerName != null) {
            deploymentInfo.setHostName(virtualServerName);
        }

        // Set the factory explicitly instead of relying on the "authconfigprovider.factory" security property.
        // This runs before ServletContextListeners, so applications can register their ServerAuthModule there.
        AuthConfigFactory.setFactory(new DefaultConfigFactory());

        // Created on the first request, so it uses the factory as left by the application's initializers
        AuthenticationServiceHolder authenticationService = new AuthenticationServiceHolder(servletContext);

        // Callers remembered with jakarta.servlet.http.registerSession, kept in line with the session lifecycle
        RegisteredSessions registeredSessions = new RegisteredSessions();
        deploymentInfo.addSessionListener(registeredSessions);

        // Replaces QuarkusAuthMechanism, which stays in use as long as no ServerAuthModule is registered
        EpicyroAuthenticationMechanism authenticationMechanism = new EpicyroAuthenticationMechanism(
                authenticationService, registeredSessions, QuarkusAuthMechanism.INSTANCE);
        deploymentInfo.setJaspiAuthenticationMechanism(authenticationMechanism);

        // validateRequest must be called for every request, not only for constrained ones
        deploymentInfo.setAuthenticationMode(PRO_ACTIVE);

        // Quarkus' exception handler runs authentication again after an UnauthorizedException, the same way
        // HttpServletRequest#authenticate() does; mark it as container-initiated
        ExceptionHandler exceptionHandler = deploymentInfo.getExceptionHandler();
        if (exceptionHandler != null) {
            deploymentInfo.setExceptionHandler((exchange, request, response, throwable) -> {
                exchange.putAttachment(CONTAINER_REAUTHENTICATION, true);
                try {
                    return exceptionHandler.handleThrowable(exchange, request, response, throwable);
                } finally {
                    exchange.removeAttachment(CONTAINER_REAUTHENTICATION);
                }
            });
        }

        // A ServerAuthModule may wrap the request and response with arbitrary wrappers
        deploymentInfo.setAllowNonStandardWrappers(true);

        deploymentInfo.addOuterHandlerChainWrapper(new SecureResponseHandlerWrapper(authenticationService));

        // HttpServletRequest#logout() calls the module's cleanSubject and clears the Quarkus identity,
        // HttpServletRequest#authenticate() always calls the module, and a registered session's principal is exposed
        // to the module
        deploymentInfo.setSecurityContextFactory(
                EpicyroSecurityContext.factory(authenticationService, registeredSessions, authenticationMechanism));
    }
}
