package org.glassfish.epicyro.quarkus.runtime;

import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.undertow.runtime.ServletHttpSecurityPolicy;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

import jakarta.inject.Singleton;

/**
 * Replaces Quarkus' {@link ServletHttpSecurityPolicy}, which enforces web.xml and {@code @ServletSecurity} constraints
 * for every request at the Vert.x level, before the request reaches Undertow.
 *
 * <p>
 * At that point the caller is still anonymous, because the {@code ServerAuthModule} only runs later, inside Undertow's
 * security chain. Jakarta Authentication requires the module to be called first (with {@code isMandatory} for
 * constrained resources) and the constraints checked against the identity it establishes. So this policy permits
 * everything, and Undertow's own constraint handlers enforce the constraints after authentication.
 *
 * <p>
 * Extends the original because Quarkus looks it up by that type to give it the servlet deployment.
 */
@Singleton
public class EpicyroServletHttpSecurityPolicy extends ServletHttpSecurityPolicy {

    @Override
    public Uni<CheckResult> checkPermission(RoutingContext request, Uni<SecurityIdentity> identity,  AuthorizationRequestContext requestContext) {
        return CheckResult.permit();
    }
}
