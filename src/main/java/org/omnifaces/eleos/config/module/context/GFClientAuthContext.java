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

package org.omnifaces.eleos.config.module.context;

import javax.security.auth.Subject;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.ClientAuthContext;
import javax.security.auth.message.module.ClientAuthModule;

public class GFClientAuthContext implements ClientAuthContext {

    private final ClientAuthModule module;

    public GFClientAuthContext(ClientAuthModule module) {
        if (module == null) {
            throw new IllegalStateException("Module should not be null");
        }
        this.module = module;
    }

    @Override
    public AuthStatus secureRequest(MessageInfo messageInfo, Subject clientSubject) throws AuthException {
        return module.secureRequest(messageInfo, clientSubject);
    }

    @Override
    public AuthStatus validateResponse(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
        return module.validateResponse(messageInfo, clientSubject, serviceSubject);
    }

    @Override
    public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
        module.cleanSubject(messageInfo, subject);
    }
}
