package org.glassfish.epicyro.quarkus.test;

import static jakarta.security.auth.message.AuthStatus.SEND_FAILURE;
import static jakarta.security.auth.message.AuthStatus.SEND_SUCCESS;
import static jakarta.security.auth.message.AuthStatus.SUCCESS;
import static jakarta.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;

import java.io.IOException;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import jakarta.security.auth.message.AuthException;
import jakarta.security.auth.message.AuthStatus;
import jakarta.security.auth.message.MessageInfo;
import jakarta.security.auth.message.MessagePolicy;
import jakarta.security.auth.message.callback.CallerPrincipalCallback;
import jakarta.security.auth.message.callback.GroupPrincipalCallback;
import jakarta.security.auth.message.module.ServerAuthModule;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Minimal SAM: a request with an {@code X-Test-User} header is authenticated as that user with the
 * group {@code architect}. Without the header it does nothing for public resources and sends a 401
 * for protected ones.
 */
public class TestServerAuthModule implements ServerAuthModule {

    public static final String USER_HEADER = "X-Test-User";
    public static final String INVOKED_HEADER = "X-Test-Sam-Invoked";
    public static final String CLEANED_HEADER = "X-Test-Sam-Cleaned";

    /** With {@link #USER_HEADER}: ask the container to remember the caller (jakarta.servlet.http.registerSession). */
    public static final String REGISTER_HEADER = "X-Test-Register";

    /** Set when the module is called for HttpServletRequest#authenticate() (isAuthenticationRequest key). */
    public static final String AUTHENTICATION_REQUEST_HEADER = "X-Test-Authentication-Request";

    /** Authenticate as this user, but only when called for HttpServletRequest#authenticate(). */
    public static final String AUTHENTICATE_AS_HEADER = "X-Test-Authenticate-As";

    /** Continue the caller registered in the session, if any. */
    public static final String CONTINUE_HEADER = "X-Test-Continue";

    private CallbackHandler handler;

    @Override
    public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler, Map<String, Object> options) throws AuthException {
        this.handler = handler;
    }

    @Override
    public Class<?>[] getSupportedMessageTypes() {
        return new Class[] { HttpServletRequest.class, HttpServletResponse.class };
    }

    @Override
    public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
        HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
        HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();

        // Lets tests see whether the SAM ran for a request
        response.setHeader(INVOKED_HEADER, "true");

        String user = request.getHeader(USER_HEADER);

        if (Boolean.parseBoolean(String.valueOf(messageInfo.getMap().get("jakarta.servlet.http.isAuthenticationRequest")))) {
            response.setHeader(AUTHENTICATION_REQUEST_HEADER, "true");
            if (request.getHeader(AUTHENTICATE_AS_HEADER) != null) {
                user = request.getHeader(AUTHENTICATE_AS_HEADER);
            }
        }
        try {
            if (request.getHeader(CONTINUE_HEADER) != null && request.getUserPrincipal() != null) {
                // The container shows a registered caller as the request's principal; passing it back continues it
                handler.handle(new Callback[] { new CallerPrincipalCallback(clientSubject, request.getUserPrincipal()) });
                return SUCCESS;
            }

            if (user != null) {
                handler.handle(new Callback[] {
                        new CallerPrincipalCallback(clientSubject, user),
                        new GroupPrincipalCallback(clientSubject, new String[] { "architect" }) });

                if (request.getHeader(REGISTER_HEADER) != null) {
                    messageInfo.getMap().put("jakarta.servlet.http.registerSession", "true");
                }
                return SUCCESS;
            }

            if (Boolean.parseBoolean(String.valueOf(messageInfo.getMap().get("jakarta.security.auth.message.MessagePolicy.isMandatory")))) {
                response.sendError(SC_UNAUTHORIZED);
                return SEND_FAILURE;
            }

            // Public resource, no credentials: "do nothing" protocol
            handler.handle(new Callback[] { new CallerPrincipalCallback(clientSubject, (String) null) });
            
            return SUCCESS;
        } catch (IOException | UnsupportedCallbackException e) {
            throw (AuthException) new AuthException().initCause(e);
        }
    }

    @Override
    public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
        return SEND_SUCCESS;
    }

    @Override
    public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
        // Lets tests see whether HttpServletRequest#logout() called cleanSubject
        ((HttpServletResponse) messageInfo.getResponseMessage()).setHeader(CLEANED_HEADER, "true");

        if (subject != null) {
            subject.getPrincipals().clear();
        }
    }
}
