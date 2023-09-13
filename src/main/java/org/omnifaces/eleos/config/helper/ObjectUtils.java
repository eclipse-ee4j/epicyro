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

import static java.security.AccessController.doPrivileged;
import static java.util.logging.Level.WARNING;
import static org.omnifaces.eleos.config.helper.ObjectUtils.createObject;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.logging.Logger;

import javax.security.auth.message.AuthException;

import org.omnifaces.eleos.config.factory.ConfigParser;

public class ObjectUtils {

    private static final Logger logger = Logger.getLogger(ObjectUtils.class.getName());

    // For loading modules
    private static final Class<?>[] EMPTY_PARAMS = {};
    private static final Object[] EMPTY_ARGS = {};

    /**
     * Create an object of a given class.
     *
     * @param className
     *
     */
    @SuppressWarnings("unchecked")
    public static <T> T createObject(String className) {
        ClassLoader loader = getClassLoader();

        if (System.getSecurityManager() != null) {
            try {
                return (T) doPrivileged((PrivilegedExceptionAction<Object>)
                    () -> Class.forName(className, true, loader).newInstance());
            } catch (PrivilegedActionException pae) {
                throw new RuntimeException(pae.getException());
            }
        }

        try {
            return (T) Class.forName(className, true, loader).newInstance();
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }
    
    public static ConfigParser newConfigParser(String parserClassName, Object config) throws IOException {
        ConfigParser newParser = createObject(parserClassName);
        newParser.initialize(config);
        
        return newParser;
    }

    public static Object newAuthModule(String moduleClassName) throws AuthException {
        return newAuthModule(moduleClassName, EMPTY_PARAMS, EMPTY_ARGS);
    }

    /**
     * Return a new instance of the module contained in this entry.
     *
     * <p>
     * The default implementation of this method attempts to invoke the default no-args constructor of the module class.
     * This method may be overridden if a different constructor should be invoked.
     *
     * @return a new instance of the module contained in this entry.
     *
     * @exception AuthException if the instantiation failed.
     */
    public static Object newAuthModule(String moduleClassName, Class<?>[] parameterTypes, Object[] initargs) throws AuthException {
        try {
            return Class.forName(moduleClassName, true, getClassLoader()).getConstructor(parameterTypes).newInstance(initargs);
        } catch (Exception e) {
            if (logger.isLoggable(WARNING)) {
                logger.log(WARNING, "jaspic.provider_unable_to_load_authmodule", new String[] { moduleClassName, e.toString() });
            }

            throw (AuthException) new AuthException().initCause(e);
        }
    }

    public static ClassLoader getClassLoader() {
        if (System.getSecurityManager() == null) {
            return Thread.currentThread().getContextClassLoader();
        }

        return (ClassLoader) AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                return Thread.currentThread().getContextClassLoader();
            }
        });
    }


}
