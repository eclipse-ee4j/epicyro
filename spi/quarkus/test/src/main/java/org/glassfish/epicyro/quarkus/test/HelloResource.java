package org.glassfish.epicyro.quarkus.test;

import java.io.IOException;

import org.glassfish.epicyro.config.factory.BaseAuthConfigFactory;

import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.security.auth.message.config.AuthConfigFactory;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.SecurityContext;

@Path("/hello")
public class HelloResource {

    @Inject
    HttpServletRequest request;

    @Inject
    SecurityIdentity securityIdentity;

    @GET
    public String hello() {
        return "hello";
    }

    /**
     * The class of the servlet request the REST endpoint sees; with quarkus-rest-servlet this is Undertow's request.
     */
    @GET
    @Path("/servlet-request")
    public String servletRequest(@Context HttpServletRequest contextRequest) {
        return contextRequest.getClass().getName();
    }

    /**
     * Whether the SAM registered by {@link SamRegistrationListener} is found for this application's context.
     */
    @GET
    @Path("/sam-registered")
    public boolean samRegistered() {
        String appContext = BaseAuthConfigFactory.getAppContextID(request.getServletContext());
        return AuthConfigFactory.getFactory().getConfigProvider("HttpServlet", appContext, null) != null;
    }

    /**
     * The caller as seen by Quarkus Security, on a resource that doesn't require authentication.
     */
    @GET
    @Path("/whoami")
    public String whoami(@Context SecurityContext securityContext) {
        return securityContext.getUserPrincipal() == null ? "anonymous" : securityContext.getUserPrincipal().getName();
    }

    /**
     * The caller as seen by Quarkus Security before and after {@link HttpServletRequest#logout()}.
     */
    @GET
    @Path("/logout")
    public String logout(@Context HttpServletRequest contextRequest) throws ServletException {
        String before = securityIdentity.isAnonymous() ? "anonymous" : securityIdentity.getPrincipal().getName();
        contextRequest.logout();
        String after = securityIdentity.isAnonymous() ? "anonymous" : securityIdentity.getPrincipal().getName();

        return before + " -> " + after;
    }

    /**
     * The outcome of {@link HttpServletRequest#authenticate(HttpServletResponse)} on a public resource, and the caller
     * after it.
     */
    @GET
    @Path("/authenticate")
    public String authenticate(@Context HttpServletRequest contextRequest, @Context HttpServletResponse contextResponse)
            throws IOException, ServletException {
        boolean authenticated = contextRequest.authenticate(contextResponse);
        return authenticated + " "
                + (contextRequest.getUserPrincipal() == null ? "anonymous" : contextRequest.getUserPrincipal().getName());
    }

    @GET
    @Path("/protected")
    @RolesAllowed("architect")
    public String protectedHello(@Context SecurityContext securityContext) {
        return "hello " + securityContext.getUserPrincipal().getName();
    }
}
