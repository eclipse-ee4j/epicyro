/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 1997-2010 Oracle and/or its affiliates. All rights reserved.
 *
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common Development
 * and Distribution License("CDDL") (collectively, the "License").  You
 * may not use this file except in compliance with the License.  You can
 * obtain a copy of the License at
 * https://glassfish.dev.java.net/public/CDDL+GPL_1_1.html
 * or packager/legal/LICENSE.txt.  See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * When distributing the software, include this License Header Notice in each
 * file and include the License file at packager/legal/LICENSE.txt.
 *
 * GPL Classpath Exception:
 * Oracle designates this particular file as subject to the "Classpath"
 * exception as provided by Oracle in the GPL Version 2 section of the License
 * file that accompanied this code.
 *
 * Modifications:
 * If applicable, add the following below the License Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyright [year] [name of copyright owner]"
 *
 * Contributor(s):
 * If you wish your version of this file to be governed by only the CDDL or
 * only the GPL Version 2, indicate your decision by adding "[Contributor]
 * elects to include this software in this distribution under the [CDDL or GPL
 * Version 2] license."  If you don't indicate a single choice of license, a
 * recipient has the option to distribute your version of this file under
 * either the CDDL, the GPL Version 2 or to extend the choice of license to
 * its licensees as provided above.  However, if you add GPL Version 2 code
 * and therefore, elected the GPL Version 2 license, then the option applies
 * only if the new code is made subject to such option by the copyright
 * holder.
 */
// Portions Copyright [2018-2019] [Payara Foundation and/or its affiliates]
package org.glassfish.epicyro.config.helper;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

/**
 * This class provides an optimization for some methods in java.security.AccessController.
 * 
 * @author Shing Wai Chan
 * @author Arjan Tijms
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

    public static Object privilegedNoCheck(Runnable runnable) {
        return AccessController.doPrivileged((PrivilegedAction<Object>) () -> {
            runnable.run();
            return null;
        });
    }

    public static <T> T privilegedNoCheck(PrivilegedAction<T> privilegedAction) {
        return AccessController.doPrivileged(privilegedAction);
    }

    public static Object doPrivileged(PrivilegedAction<?> action) {
        if (hasSecurityManager) {
            return AccessController.doPrivileged(action);
        }

        return action.run();
    }

    public static Object doPrivileged(PrivilegedExceptionAction<Object> privilegedExceptionAction) throws PrivilegedActionException {
        if (hasSecurityManager) {
            return AccessController.doPrivileged(privilegedExceptionAction);
        }

        try {
            return privilegedExceptionAction.run();
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        }

    }

    public static <T> T privileged(PrivilegedAction<T> privilegedAction) {
        if (hasSecurityManager) {
            return AccessController.doPrivileged(privilegedAction);
        }

        return privilegedAction.run();
    }

    public static Object privileged(Runnable runnable) {
        if (hasSecurityManager) {
            return AccessController.doPrivileged((PrivilegedAction<Object>) () -> {
                runnable.run();
                return null;
            });
        }

        runnable.run();
        return null;
    }

}
