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

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

/**
 * This class provides an optimization for some methods in java.security.AccessController.
 * 
 * @author Shing Wai Chan
 */
public final class PriviledgedAccessController {
    private static boolean hasSecurityManager = System.getSecurityManager() != null;

    private PriviledgedAccessController() {
    }
    
    public static void privilegedWithException(Runnable runnable) throws PrivilegedActionException {
        if (hasSecurityManager) {
            AccessController.doPrivileged((PrivilegedExceptionAction<Object>) () -> {
                runnable.run();
                return null;
            });

        }
        
        try {
            runnable.run();
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        }
    }

    public static Object doPrivileged(PrivilegedAction<Object> action) {
        if (hasSecurityManager) {
            return AccessController.doPrivileged(action);
        }
        
        return action.run();
            
        
    }

    public static Object doPrivileged(PrivilegedExceptionAction<Object> action) throws PrivilegedActionException {
        if (hasSecurityManager) {
            return AccessController.doPrivileged(action);
        } 
        
        try {
            return action.run();
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        }
        
    }
}
