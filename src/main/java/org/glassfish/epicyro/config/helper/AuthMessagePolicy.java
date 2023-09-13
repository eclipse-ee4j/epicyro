/*
 * Copyright (c) 1997, 2018 Oracle and/or its affiliates. All rights reserved.
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

package org.glassfish.epicyro.config.helper;


import static jakarta.security.auth.message.MessagePolicy.ProtectionPolicy.AUTHENTICATE_CONTENT;
import static jakarta.security.auth.message.MessagePolicy.ProtectionPolicy.AUTHENTICATE_RECIPIENT;
import static jakarta.security.auth.message.MessagePolicy.ProtectionPolicy.AUTHENTICATE_SENDER;

import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;
import jakarta.security.auth.message.MessagePolicy;
import jakarta.security.auth.message.MessagePolicy.TargetPolicy;


public class AuthMessagePolicy {

    private static boolean isSecMgrOff = System.getSecurityManager() == null;

    private static final String SENDER = "sender";
    private static final String CONTENT = "content";
    private static final String BEFORE_CONTENT = "before-content";
    private static final String HANDLER_CLASS_PROPERTY = "security.jaspic.config.ConfigHelper.CallbackHandler";
    private static final String DEFAULT_HANDLER_CLASS = ServerCallbackHandler.class.getName();

    // for HttpServlet profile
    private static final MessagePolicy MANDATORY_POLICY = getMessagePolicy(SENDER, null, true);
    private static final MessagePolicy OPTIONAL_POLICY = getMessagePolicy(SENDER, null, false);

    private static String handlerClassName;

    private AuthMessagePolicy() {
    }

    public static MessagePolicy getMessagePolicy(String authSource, String authRecipient) {
        boolean sourceSender = SENDER.equals(authSource);
        boolean sourceContent = CONTENT.equals(authSource);
        boolean recipientAuth = authRecipient != null;
        boolean mandatory = (sourceSender || sourceContent) || recipientAuth;

        return getMessagePolicy(authSource, authRecipient, mandatory);
    }

    public static MessagePolicy getMessagePolicy(String authSource, String authRecipient, boolean mandatory) {
        boolean sourceSender = SENDER.equals(authSource);
        boolean sourceContent = CONTENT.equals(authSource);
        boolean recipientAuth = authRecipient != null;
        boolean beforeContent = BEFORE_CONTENT.equals(authRecipient);

        List<TargetPolicy> targetPolicies = new ArrayList<TargetPolicy>();

        if (recipientAuth && beforeContent) {
            targetPolicies.add(new TargetPolicy(null, () -> AUTHENTICATE_RECIPIENT));

            if (sourceSender) {
                targetPolicies.add(new TargetPolicy(null, () -> AUTHENTICATE_SENDER));
            } else if (sourceContent) {
                targetPolicies.add(new TargetPolicy(null, () -> AUTHENTICATE_CONTENT));
            }
        } else {
            if (sourceSender) {
                targetPolicies.add(new TargetPolicy(null, () -> AUTHENTICATE_SENDER));
            } else if (sourceContent) {
                targetPolicies.add(new TargetPolicy(null, () -> AUTHENTICATE_CONTENT));
            }

            if (recipientAuth) {
                targetPolicies.add(new TargetPolicy(null, () -> AUTHENTICATE_RECIPIENT));
            }
        }

        return new MessagePolicy(targetPolicies.toArray(new TargetPolicy[targetPolicies.size()]), mandatory);
    }


    public static MessagePolicy[] getHttpServletPolicies(String authContextID) {
        if (Boolean.valueOf(authContextID)) {
            return new MessagePolicy[] { MANDATORY_POLICY, null };
        }

        return new MessagePolicy[] { OPTIONAL_POLICY, null };
    }

    public static CallbackHandler getDefaultCallbackHandler() {
        // Get the default handler class
        try {
            return (CallbackHandler) doPrivileged(new PrivilegedExceptionAction<Object>() {
                @Override
                public Object run() throws Exception {
                    ClassLoader loader = Thread.currentThread().getContextClassLoader();
                    if (handlerClassName == null) {
                        handlerClassName = System.getProperty(HANDLER_CLASS_PROPERTY, DEFAULT_HANDLER_CLASS);
                    }

                    return Class.forName(handlerClassName, true, loader)
                                .newInstance();
                }
            });

        } catch (PrivilegedActionException pae) {
            throw new RuntimeException(pae.getException());
        }
    }

    public static Object doPrivileged(PrivilegedExceptionAction<Object> action) throws PrivilegedActionException {
        if (isSecMgrOff) {
            try {
                return action.run();
            } catch(Exception e) {
                throw new PrivilegedActionException(e);
            }
        } else {
            return AccessController.doPrivileged(action);
        }
    }

}
