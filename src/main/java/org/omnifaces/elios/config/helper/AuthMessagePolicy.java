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

package org.omnifaces.elios.config.helper;

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.MessagePolicy.ProtectionPolicy;
import javax.security.auth.message.MessagePolicy.TargetPolicy;

/**
 * Utility class for JMAC appserver implementation.
 */
public class AuthMessagePolicy {

    private static final String SENDER = "sender";
    private static final String CONTENT = "content";
    private static final String BEFORE_CONTENT = "before-content";
    private static final String HANDLER_CLASS_PROPERTY = "security.jmac.config.ConfigHelper.CallbackHandler";
    private static final String DEFAULT_HANDLER_CLASS = "com.sun.enterprise.security.jmac.callback.ContainerCallbackHandler";

    // for HttpServlet profile
    private static final MessagePolicy MANDATORY_POLICY = getMessagePolicy(SENDER, null, true);
    private static final MessagePolicy OPTIONAL_POLICY = getMessagePolicy(SENDER, null, false);

    private static String handlerClassName = null;

    private AuthMessagePolicy() {
    };


    public static MessagePolicy getMessagePolicy(String authSource, String authRecipient) {
        boolean sourceSender = SENDER.equals(authSource);
        boolean sourceContent = CONTENT.equals(authSource);
        boolean recipientAuth = (authRecipient != null);
        boolean mandatory = (sourceSender || sourceContent) || recipientAuth;
        return getMessagePolicy(authSource, authRecipient, mandatory);
    }

    public static MessagePolicy getMessagePolicy(String authSource, String authRecipient, boolean mandatory) {

        boolean sourceSender = SENDER.equals(authSource);
        boolean sourceContent = CONTENT.equals(authSource);
        boolean recipientAuth = (authRecipient != null);
        boolean beforeContent = BEFORE_CONTENT.equals(authRecipient);

        List<TargetPolicy> targetPolicies = new ArrayList<TargetPolicy>();
        if (recipientAuth && beforeContent) {
            targetPolicies.add(new TargetPolicy(null, new ProtectionPolicy() {
                public String getID() {
                    return ProtectionPolicy.AUTHENTICATE_RECIPIENT;
                }
            }));
            if (sourceSender) {
                targetPolicies.add(new TargetPolicy(null, new ProtectionPolicy() {
                    public String getID() {
                        return ProtectionPolicy.AUTHENTICATE_SENDER;
                    }
                }));
            } else if (sourceContent) {
                targetPolicies.add(new TargetPolicy(null, new ProtectionPolicy() {
                    public String getID() {
                        return ProtectionPolicy.AUTHENTICATE_CONTENT;
                    }
                }));
            }
        } else {
            if (sourceSender) {
                targetPolicies.add(new TargetPolicy(null, new ProtectionPolicy() {
                    public String getID() {
                        return ProtectionPolicy.AUTHENTICATE_SENDER;
                    }
                }));
            } else if (sourceContent) {
                targetPolicies.add(new TargetPolicy(null, new ProtectionPolicy() {
                    public String getID() {
                        return ProtectionPolicy.AUTHENTICATE_CONTENT;
                    }
                }));
            }

            if (recipientAuth) {
                targetPolicies.add(new TargetPolicy(null, new ProtectionPolicy() {
                    public String getID() {
                        return ProtectionPolicy.AUTHENTICATE_RECIPIENT;
                    }
                }));
            }
        }

        return new MessagePolicy(targetPolicies.toArray(new TargetPolicy[targetPolicies.size()]), mandatory);
    }

    public static MessagePolicy[] getHttpServletPolicies(String authContextID) {
        if (Boolean.valueOf(authContextID)) {
            return new MessagePolicy[] { MANDATORY_POLICY, null };
        } else {
            return new MessagePolicy[] { OPTIONAL_POLICY, null };
        }
    }

    public static CallbackHandler getDefaultCallbackHandler() {
        // get the default handler class
        try {
            CallbackHandler rvalue = (CallbackHandler) PriviledgedAccessController.doPrivileged(new PrivilegedExceptionAction() {
                public Object run() throws Exception {
                    ClassLoader loader = Thread.currentThread().getContextClassLoader();
                    if (handlerClassName == null) {
                        handlerClassName = System.getProperty(HANDLER_CLASS_PROPERTY, DEFAULT_HANDLER_CLASS);
                    }
                    final String className = handlerClassName;
                    Class c = Class.forName(className, true, loader);
                    return c.newInstance();
                }
            });
            return rvalue;

        } catch (PrivilegedActionException pae) {
            throw new RuntimeException(pae.getException());
        }
    }

}
