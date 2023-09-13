/*
 * Copyright (c) 2015, 2018 Oracle and/or its affiliates. All rights reserved.
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

package org.omnifaces.eleos.config.delegate;

import static javax.security.auth.message.MessagePolicy.ProtectionPolicy.AUTHENTICATE_SENDER;

import java.util.Map;

import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.MessagePolicy.TargetPolicy;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ServletMessagePolicyDelegate implements MessagePolicyDelegate {

    private static final String MANDATORY_AUTH_CONTEXT_ID = "mandatory";
    private static final String OPTIONAL_AUTH_CONTEXT_ID = "optional";
    private static final String MANDATORY_KEY = "javax.security.auth.message.MessagePolicy.isMandatory";

    private static final Class<?>[] MESSAGE_TYPES = new Class[] { HttpServletRequest.class, HttpServletResponse.class };

    private static final MessagePolicy mandatoryPolicy = new MessagePolicy(new TargetPolicy[] { new TargetPolicy(null, () -> AUTHENTICATE_SENDER) }, true);
    private static final MessagePolicy optionalPolicy = new MessagePolicy(new TargetPolicy[] { new TargetPolicy(null, () -> AUTHENTICATE_SENDER) }, false);
    
    @Override
    public Class<?>[] getMessageTypes() {
        return MESSAGE_TYPES;
    }
    
    @Override
    public MessagePolicy getRequestPolicy(String authContextID, Map properties) {
        return MANDATORY_AUTH_CONTEXT_ID.equals(authContextID) ? mandatoryPolicy : optionalPolicy;
    }

    @Override
    public MessagePolicy getResponsePolicy(String authContextID, Map properties) {
        return null;
    }

    @Override
    public String getAuthContextID(MessageInfo messageInfo) {
        return messageInfo.getMap().containsKey(MANDATORY_KEY) ? MANDATORY_AUTH_CONTEXT_ID : OPTIONAL_AUTH_CONTEXT_ID;
    }

    @Override
    public boolean isProtected() {
        return true;
    }

};