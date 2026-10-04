/*
 * Copyright (c) 2021 OmniFaces. All rights reserved.
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

import static jakarta.security.auth.message.AuthStatus.SEND_FAILURE;
import static jakarta.security.auth.message.AuthStatus.SEND_SUCCESS;
import static jakarta.security.auth.message.AuthStatus.SUCCESS;
import static jakarta.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;

import java.io.IOException;
import java.security.Principal;
import java.util.Base64;
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
import jakarta.security.auth.message.callback.PasswordValidationCallback;
import jakarta.security.auth.message.module.ServerAuthModule;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 *
 * @author Arjan Tijms
 *
 */
public class BasicServerAuthModule implements ServerAuthModule {

    private CallbackHandler handler;
    private String realm;

    @Override
    public Class<?>[] getSupportedMessageTypes() {
        return new Class[] { HttpServletRequest.class, HttpServletResponse.class };
    }

    @Override
    public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler,
            @SuppressWarnings("rawtypes") Map options) throws AuthException {
        this.handler = handler;
        realm = (String) options.get("realmName");
    }

    @Override
    public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
        try {
            HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
            HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();

            String[] credentials = getCredentials(request);

            if (credentials != null) {
                PasswordValidationCallback passwordValidation =
                    new PasswordValidationCallback(clientSubject,
                        credentials[0],
                        credentials[1].toCharArray());

                handler.handle(new Callback[] { passwordValidation });

                if (passwordValidation.getResult()) {
                    return SUCCESS;
                }
            }

            if (isProtectedResource(messageInfo)) {
                response.setHeader("WWW-Authenticate", String.format("Basic realm=\"%s\"", realm));
                response.sendError(SC_UNAUTHORIZED);

                return SEND_FAILURE;
            }

            handler.handle(new Callback[] { new CallerPrincipalCallback(clientSubject, (Principal) null) });
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
    }

    private String[] getCredentials(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Basic ")) {
            return new String(Base64.getDecoder().decode(authorizationHeader.substring(6))).split(":");
        }

        return null;
    }

    public static boolean isProtectedResource(MessageInfo messageInfo) {
        return Boolean.valueOf((String) messageInfo.getMap().get("jakarta.security.auth.message.MessagePolicy.isMandatory"));
    }
}