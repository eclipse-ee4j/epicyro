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

package org.omnifaces.eleos.config.helper;

import java.util.Map;

import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;

/**
 * The modules manager
 *
 * @author Ron Monzillo
 */
public abstract class ModulesManager {
    private boolean returnNullContexts;

    protected ModulesManager(boolean returnNullContexts) {
        this.returnNullContexts = returnNullContexts;
    }

    public boolean returnsNullContexts() {
        return returnNullContexts;
    }

    public <M> boolean isProtected(M[] template, String authContextID) throws AuthException {
        try {
            if (returnNullContexts) {
                return hasModules(template, authContextID);
            }

            return true;

        } catch (AuthException ae) {
            throw new RuntimeException(ae);
        }
    }

    public abstract <M> boolean hasModules(M[] template, String authContextID) throws AuthException;

    public abstract <M> M[] getModules(M[] template, String authContextID) throws AuthException;

    public abstract Map<String, ?> getInitProperties(int moduleNumber, Map<String, ?> properties);

    public abstract boolean shouldStopProcessingModules(AuthStatus[] successValue, int moduleNumber, AuthStatus moduleStatus);

    public abstract AuthStatus getReturnStatus(AuthStatus[] successValue, AuthStatus defaultFailStatus, AuthStatus[] status, int position);

    public abstract void refresh();


    // ### Protected methods

}
