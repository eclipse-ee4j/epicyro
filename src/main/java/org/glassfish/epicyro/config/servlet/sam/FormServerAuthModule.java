/*
 * Copyright (c) 2015, 2020 Oracle and/or its affiliates. All rights reserved.
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

package org.glassfish.epicyro.config.servlet.sam;

import static jakarta.security.auth.message.AuthStatus.SEND_CONTINUE;
import static jakarta.security.auth.message.AuthStatus.SEND_FAILURE;
import static jakarta.security.auth.message.AuthStatus.SEND_SUCCESS;
import static jakarta.security.auth.message.AuthStatus.SUCCESS;
import static java.lang.Boolean.TRUE;
import static org.glassfish.epicyro.config.servlet.sam.Utils.getBaseURL;
import static org.glassfish.epicyro.config.servlet.sam.Utils.isEmpty;
import static org.glassfish.epicyro.config.servlet.sam.Utils.notNull;

import java.io.IOException;
import java.security.Principal;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;

import org.glassfish.epicyro.config.helper.Caller;

import jakarta.security.auth.message.AuthException;
import jakarta.security.auth.message.AuthStatus;
import jakarta.security.auth.message.MessageInfo;
import jakarta.security.auth.message.MessagePolicy;
import jakarta.security.auth.message.callback.CallerPrincipalCallback;
import jakarta.security.auth.message.callback.GroupPrincipalCallback;
import jakarta.security.auth.message.callback.PasswordValidationCallback;
import jakarta.security.auth.message.module.ServerAuthModule;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * Authentication mechanism that authenticates according to the Servlet spec defined FORM
 * authentication mechanism. See Servlet spec for further details.
 *
 * @author Arjan Tijms
 *
 */
public class FormServerAuthModule implements ServerAuthModule {

    // Key in the MessageInfo Map that when present AND set to true indicated a protected resource is being accessed.
    // When the resource is not protected, GlassFish omits the key altogether. WebSphere does insert the key and sets
    // it to false.
    private static final String IS_MANDATORY = "jakarta.security.auth.message.MessagePolicy.isMandatory";
    public static final String IS_AUTHENTICATION = "org.glassfish.elios.security.message.request.authentication";
    public static final String IS_NEW_AUTHENTICATION = "org.glassfish.elios.security.message.request.new.authentication";
    private static final String ORIGINAL_REQUEST_DATA_SESSION_NAME = "org.glassfish.elios.original.request";
    private static final String AUTHENTICATION_DATA_SESSION_NAME = "org.glassfish.elios.authentication";
    private static final String CALLER_INITIATED_AUTHENTICATION_SESSION_NAME = "org.glassfish.elios.caller_initiated_authentication";

    private CallbackHandler handler;
    private String loginPage = "";
    private String errorPage = "";
    boolean useForwardToLogin = true;

    @Override
    public Class<?>[] getSupportedMessageTypes() {
        return new Class[] { HttpServletRequest.class, HttpServletResponse.class };
    }

    @Override
    public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler,
            @SuppressWarnings("rawtypes") Map options) throws AuthException {
        this.handler = handler;
        loginPage = (String) options.get("formLoginPage");
        errorPage = (String) options.get("formErrorPage");
    }

    @Override
    public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
        try {
            return validateRequestAutoApplySession(messageInfo, clientSubject, serviceSubject);
        } catch (Exception e) {
            AuthException authException = new AuthException();
            authException.initCause(e);
            throw authException;
        }
    }

    @Override
    public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
        return SEND_SUCCESS;
    }

    @Override
    public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
        // TODO Auto-generated method stub

    }

    @SuppressWarnings("unchecked")
    public AuthStatus validateRequestAutoApplySession(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws Exception {
        Principal userPrincipal = getPrincipal((HttpServletRequest)messageInfo.getRequestMessage());

        if (userPrincipal != null) {
            handler.handle(new Callback[] {
                new CallerPrincipalCallback(clientSubject, userPrincipal) }
            );

            return SUCCESS;
        }

        AuthStatus outcome = validateRequestLoginToContinue(messageInfo, clientSubject, serviceSubject);

        if (SUCCESS.equals(outcome)) {
            messageInfo.getMap().put("jakarta.servlet.http.registerSession", TRUE.toString());
        }

        return outcome;
    }

    public AuthStatus validateRequestLoginToContinue(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws Exception {
        HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();

        // Check if there's any state lingering behind from a previous aborted authentication dialog
        tryClean(messageInfo, request);

        if (isCallerInitiatedAuthentication(request)) {
            // The caller explicitly initiated the authentication dialog, i.e. by clicking on a login button,
            // in response to which the application called HttpServletRequest#authenticate
            return processCallerInitiatedAuthentication(messageInfo, clientSubject, serviceSubject);
        } else {
            // If the caller didn't initiated the dialog, the container did, i.e. after the caller tried to access
            // a protected resource.
            return processContainerInitiatedAuthentication(messageInfo, clientSubject, serviceSubject);
        }
    }

    public AuthStatus validateRequestForm(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws Exception {
        HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();

        if (!isValidFormPostback(request)) {
            handler.handle(new Callback[] { new CallerPrincipalCallback(clientSubject, (Principal) null) });
            return SUCCESS;
        }

        PasswordValidationCallback passwordValidation =
            new PasswordValidationCallback(clientSubject,
                request.getParameter("j_username"),
                request.getParameter("j_password").toCharArray());

        handler.handle(new Callback[] { passwordValidation });

        if (passwordValidation.getResult()) {
            return SUCCESS;
        }

        return SEND_FAILURE;
    }




    // ### Private methods


    private void tryClean(MessageInfo messageInfo, HttpServletRequest request) {

        // 1. Check if caller aborted earlier flow and does a new request to protected resource
        if (isOnProtectedURLWithStaleData(messageInfo, request)) {
            removeSavedRequest(request);
            removeCallerInitiatedAuthentication(request);
        }

        // 2. Check if caller aborted earlier flow and explicitly initiated a new authentication dialog
        if (isNewAuthentication(request)) {
            saveCallerInitiatedAuthentication(request);
            removeSavedRequest(request);
            removeSavedAuthentication(request);
        }
    }

    private AuthStatus processCallerInitiatedAuthentication(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws Exception {
        HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();

        // Try to authenticate with the next interceptor or actual authentication mechanism
        AuthStatus authstatus;

        try {
            authstatus = validateRequestForm(messageInfo, clientSubject, serviceSubject);
        } catch (AuthException e) {
            authstatus = AuthStatus.SEND_FAILURE;
        }

        if (authstatus == SUCCESS) {

            Caller caller = Caller.fromSubject(clientSubject); // Eleos specific type
            if (caller == null || caller.getCallerPrincipal() == null) {
                return SUCCESS;
            }

            // Actually authenticated now, so we remove the authentication dialog marker
            removeCallerInitiatedAuthentication(request);

            // TODO: for some mechanisms, such as OAuth the caller would now likely be at an
            // application OAuth landing page, and should likely be returned to "some other" location
            // (e.g. the page from which a login link was clicked in say a top menu bar)
            //
            // Do we add support for this, e.g. via a watered down savedRequest (saving only a caller provided URL)
            // Or do we leave this as an application responsibility?
        }

        return authstatus;
    }

    private AuthStatus processContainerInitiatedAuthentication(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws Exception {
        HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
        HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();

        // 1. Protected resource requested and no request saved before
        if (isOnInitialProtectedURL(messageInfo, request)) {

            // Save request details and redirect/forward to /login page
            saveRequest(request);

            if (useForwardToLogin) {
                return forward(loginPage, request, response);
            } else {
                return redirect(getBaseURL(request) + loginPage, response);
            }
        }


        // 2. A postback after we have redirected the caller in step 1.
        //    NOTE: this does not have to be the resource we redirected the caller to.
        //          E.g. we can redirect to /login, and /login can postback to J_SECURITY_CHECK or /login2,
        //          or whatever. For each such postback we give the authentication mechanism the opportunity
        //          to authenticate though.
        if (isOnLoginPostback(request)) {
            // Try to authenticate with the next interceptor or actual authentication mechanism
            AuthStatus authstatus;

            try {
                authstatus = validateRequestForm(messageInfo, clientSubject, serviceSubject);
            } catch (AuthException e) {
                authstatus = AuthStatus.SEND_FAILURE;
            }

            // (Following the Jakarta Authentication spec (3.8.3.1) validateRequest before service invocation can only return
            // SUCCESS, SEND_CONTINUE, SEND_FAILURE or throw an exception
            if (authstatus == SUCCESS) {

                Caller caller = Caller.fromSubject(clientSubject); // Eleos specific type
                if (caller == null || caller.getCallerPrincipal() == null || caller.getCallerPrincipal().getName() == null) {
                    return SUCCESS;
                }

                // Authentication was successful and an actual caller principal was set
                RequestData savedRequest = getSavedRequest(request);

                // Check if we're already on the right target URL
                if  (!savedRequest.matchesRequest(request)) {

                    // Store the authenticated data before redirecting to the right
                    // URL. This is needed since the underlying Jakarta Authentication runtime does not
                    // remember the authenticated identity if we redirect.
                    saveAuthentication(request, new AuthenticationData(
                            caller.getCallerPrincipal(),
                            caller.getGroups()));

                    return redirect(savedRequest.getFullRequestURL(), response);
                } // else return success

            } else if (authstatus == AuthStatus.SEND_FAILURE)  {
                if (isEmpty(errorPage)) {
                    return authstatus;
                }

                return redirect(getBaseURL(request) + errorPage, response);
            } else {
                // Basically SEND_CONTINUE
                return authstatus;
            }
        }


        // 3. Authenticated data saved and back on original URL from step 1.
        if (isOnOriginalURLAfterAuthenticate(request)) {

            // Remove all the data we saved
            RequestData requestData = removeSavedRequest(request);
            AuthenticationData authenticationData = removeSavedAuthentication(request);

            // Wrap the request to provide all the original request data again, such as the original
            // headers and the HTTP method, authenticate and then invoke the originally requested resource
            messageInfo.setRequestMessage(new HttpServletRequestDelegator(request, requestData));

            handler.handle(new Callback[] {
                    new CallerPrincipalCallback(clientSubject, authenticationData.getPrincipal()),
                    new GroupPrincipalCallback(clientSubject, authenticationData.getGroups().toArray(String[]::new))
            });

            return SUCCESS;
        }

        return validateRequestForm(messageInfo, clientSubject, serviceSubject);

    }

    private boolean isCallerInitiatedAuthentication(HttpServletRequest request) {
        return TRUE.equals(getCallerInitiatedAuthentication(request));
    }

    private boolean isOnProtectedURLWithStaleData(MessageInfo messageInfo, HttpServletRequest request) {
        return
            isProtected(messageInfo) &&

            // When HttpServletRequest#authenticate is called, it counts as "mandated" authentication
            // which here means isProtected() is true. But we want to use HttpServletRequest#authenticate
            // to resume a dialog started by accessing a protected page, so therefore exclude it here.
            !isAuthenticationRequest(request) &&
            getSavedRequest(request) != null &&
            getSavedAuthentication(request) == null &&

            // Some servers consider the Servlet special URL "/j_security_check" as
            // a protected URL
            !request.getRequestURI().endsWith("j_security_check");
    }

    private boolean isOnInitialProtectedURL(MessageInfo messageInfo, HttpServletRequest request) {
        return
            isProtected(messageInfo) &&

            // When HttpServletRequest#authenticate is called, it counts as "mandated" authentication
            // which here means isProtected() is true. But we want to use HttpServletRequest#authenticate
            // to resume a dialog started by accessing a protected page, so therefore exclude it here.
            !isAuthenticationRequest(request) &&
            getSavedRequest(request) == null &&
            getSavedAuthentication(request) == null &&

            // Some servers consider the Servlet special URL "/j_security_check" as
            // a protected URL
            !request.getRequestURI().endsWith("j_security_check");
    }

    private boolean isOnLoginPostback(HttpServletRequest request) {
        return
            getSavedRequest(request) != null &&
            getSavedAuthentication(request) == null;
    }

    private boolean isOnOriginalURLAfterAuthenticate(HttpServletRequest request) {
        RequestData savedRequest = getSavedRequest(request);
        AuthenticationData authenticationData = getSavedAuthentication(request);

        return
            notNull(savedRequest, authenticationData) &&
            savedRequest.matchesRequest(request);
    }

    private void saveCallerInitiatedAuthentication(HttpServletRequest request) {
        request.getSession().setAttribute(CALLER_INITIATED_AUTHENTICATION_SESSION_NAME, TRUE);
    }

    private Boolean getCallerInitiatedAuthentication(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }

        return (Boolean) session.getAttribute(CALLER_INITIATED_AUTHENTICATION_SESSION_NAME);
    }

    private void removeCallerInitiatedAuthentication(HttpServletRequest request) {
        request.getSession().removeAttribute(CALLER_INITIATED_AUTHENTICATION_SESSION_NAME);
    }

    private void saveRequest(HttpServletRequest request) {
        request.getSession().setAttribute(ORIGINAL_REQUEST_DATA_SESSION_NAME, RequestData.of(request));
    }

    private RequestData getSavedRequest(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }

        return (RequestData) session.getAttribute(ORIGINAL_REQUEST_DATA_SESSION_NAME);
    }

    private RequestData removeSavedRequest(HttpServletRequest request) {
        RequestData requestData = getSavedRequest(request);

        request.getSession().removeAttribute(ORIGINAL_REQUEST_DATA_SESSION_NAME);

        return requestData;
    }

    private void saveAuthentication(HttpServletRequest request, AuthenticationData authenticationData) {
        request.getSession().setAttribute(AUTHENTICATION_DATA_SESSION_NAME, authenticationData);
    }

    private AuthenticationData getSavedAuthentication(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }

        return (AuthenticationData) session.getAttribute(AUTHENTICATION_DATA_SESSION_NAME);
    }

    private AuthenticationData removeSavedAuthentication(HttpServletRequest request) {
        AuthenticationData authenticationData = getSavedAuthentication(request);

        request.getSession().removeAttribute(AUTHENTICATION_DATA_SESSION_NAME);

        return authenticationData;
    }



    // ### Static helper methods

    private static boolean isProtected(MessageInfo messageInfo) {
        return Boolean.valueOf((String) messageInfo.getMap().get(IS_MANDATORY));
    }

    private static boolean isAuthenticationRequest(HttpServletRequest request) {
        return TRUE.equals(request.getAttribute(IS_AUTHENTICATION));
    }

    private static boolean isNewAuthentication(HttpServletRequest request) {
        return TRUE.equals(request.getAttribute(IS_NEW_AUTHENTICATION));
    }

    private static AuthStatus redirect(String location, HttpServletResponse response) {
        Utils.redirect(response, location);

        return SEND_CONTINUE;
    }

    private static AuthStatus forward(String path, HttpServletRequest request, HttpServletResponse response) {
        try {
            request.getRequestDispatcher(path)
                    .forward(request, response);
        } catch (IOException | ServletException e) {
            throw new IllegalStateException(e);
        }

        // After forward MUST NOT invoke the resource, so CAN NOT return SUCCESS here.
        return SEND_CONTINUE;
    }


	private static boolean isValidFormPostback(HttpServletRequest request) {
	    return
            "POST".equals(request.getMethod()) &&
            request.getRequestURI().endsWith("/j_security_check") &&
            notNull(request.getParameter("j_username"), request.getParameter("j_password"));
	}

    private Principal getPrincipal(HttpServletRequest request) {
        return request.getUserPrincipal();
    }


}
