package org.glassfish.epicyro.quarkus.runtime;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.glassfish.epicyro.config.helper.BaseCallbackHandler;

import io.quarkus.arc.Arc;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.credential.PasswordCredential;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import jakarta.security.auth.message.callback.CallerPrincipalCallback;
import jakarta.security.auth.message.callback.CertStoreCallback;
import jakarta.security.auth.message.callback.GroupPrincipalCallback;
import jakarta.security.auth.message.callback.PasswordValidationCallback;
import jakarta.security.auth.message.callback.PrivateKeyCallback;
import jakarta.security.auth.message.callback.SecretKeyCallback;
import jakarta.security.auth.message.callback.TrustStoreCallback;

/**
 * Callback handler that validates credentials against the Quarkus identity providers (Elytron properties, JDBC,
 * LDAP, JPA, ...), the same ones Basic and Form authentication use.
 */
public class QuarkusCallbackHandler extends BaseCallbackHandler {

    @Override
    protected boolean isSupportedCallback(Callback callback) {
        return callback instanceof CertStoreCallback
                || callback instanceof PasswordValidationCallback
                || callback instanceof CallerPrincipalCallback
                || callback instanceof GroupPrincipalCallback
                || callback instanceof SecretKeyCallback
                || callback instanceof PrivateKeyCallback
                || callback instanceof TrustStoreCallback;
    }

    @Override
    protected void handleSupportedCallbacks(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            processCallback(callback);
        }
    }

    @Override
    protected void processPasswordValidation(PasswordValidationCallback passwordValidation) {
        IdentityProviderManager identityProviderManager = Arc.container().instance(IdentityProviderManager.class).get();

        SecurityIdentity identity;
        try {
            identity = identityProviderManager.authenticateBlocking(new UsernamePasswordAuthenticationRequest(
                    passwordValidation.getUsername(), new PasswordCredential(passwordValidation.getPassword())));
        } catch (AuthenticationFailedException e) {
            passwordValidation.setResult(false);
            return;
        }

        if (identity == null || identity.isAnonymous()) {
            passwordValidation.setResult(false);
            return;
        }

        try {
            processCallback(new CallerPrincipalCallback(passwordValidation.getSubject(), identity.getPrincipal()));
            if (!identity.getRoles().isEmpty()) {
                processCallback(new GroupPrincipalCallback(passwordValidation.getSubject(),
                        identity.getRoles().toArray(new String[0])));
            }
        } catch (UnsupportedCallbackException e) {
            throw new IllegalStateException(e);
        }

        passwordValidation.setResult(true);
    }
}
