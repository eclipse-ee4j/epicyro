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

/*
 * BaseContainerCallbackHandler.java
 *
 * Created on April 21, 2004, 11:56 AM
 */

package org.omnifaces.eleos.config.helper;

import java.io.IOException;
import java.security.Principal;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.CertStoreCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.callback.PasswordValidationCallback;
import javax.security.auth.message.callback.PrivateKeyCallback;
import javax.security.auth.message.callback.SecretKeyCallback;
import javax.security.auth.message.callback.TrustStoreCallback;

public abstract class BaseCallbackHandler implements CallbackHandler {

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        if (callbacks == null) {
            return;
        }

        for (Callback callback : callbacks) {
            if (!isSupportedCallback(callback)) {
                throw new UnsupportedCallbackException(callback);
            }
        }

        handleSupportedCallbacks(callbacks);
    }

    protected void processCallback(Callback callback) throws UnsupportedCallbackException {
        if (callback instanceof CallerPrincipalCallback) {
            processCallerPrincipal((CallerPrincipalCallback) callback);
        } else if (callback instanceof GroupPrincipalCallback) {
            processGroupPrincipal((GroupPrincipalCallback) callback);
        } else if (callback instanceof PasswordValidationCallback) {
            processPasswordValidation((PasswordValidationCallback) callback);
        } else if (callback instanceof PrivateKeyCallback) {
            processPrivateKey((PrivateKeyCallback) callback);
        } else if (callback instanceof TrustStoreCallback) {
            TrustStoreCallback tstoreCallback = (TrustStoreCallback) callback;
            tstoreCallback.setTrustStore(null);
        } else if (callback instanceof CertStoreCallback) {
            processCertStore((CertStoreCallback) callback);
        } else if (callback instanceof SecretKeyCallback) {
            processSecretKey((SecretKeyCallback) callback);
        } else {
            throw new UnsupportedCallbackException(callback);
        }
    }
    
    private void processCallerPrincipal(CallerPrincipalCallback callerPrincipalCallback) {
        Subject subject = callerPrincipalCallback.getSubject();
        Principal principal = callerPrincipalCallback.getPrincipal();
        
        if (principal == null) {
            principal = new CallerPrincipal(callerPrincipalCallback.getName());
        }
        
        Caller.toSubject(subject, new Caller(principal));
    }
    
    private void processGroupPrincipal(GroupPrincipalCallback groupCallback) {
        Subject subject = groupCallback.getSubject();
        String[] groups = groupCallback.getGroups();
        
        Caller caller = Caller.fromSubject(subject);

        if (groups != null && groups.length > 0) {
            if (caller == null) {
                Caller.toSubject(subject, new Caller(groups)); 
            } else {
                caller.addGroups(groups);
            }
        } else if (groups == null && caller != null) {
            caller.getGroups().clear();
        }
    }
    
    private void processPasswordValidation(PasswordValidationCallback pwdCallback) {
        
    }
    
    private void processPrivateKey(PrivateKeyCallback privKeyCallback) {
        
    }
    
    private void processCertStore(CertStoreCallback certStoreCallback) {
        
    }
    
    private void processSecretKey(SecretKeyCallback secretKeyCallback) {
        
    }
    
    protected abstract boolean isSupportedCallback(Callback callback);

    protected abstract void handleSupportedCallbacks(Callback[] callbacks) throws IOException, UnsupportedCallbackException;

}
