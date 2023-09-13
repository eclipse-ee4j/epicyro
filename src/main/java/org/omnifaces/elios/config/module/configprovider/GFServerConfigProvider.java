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

package org.omnifaces.elios.config.module.configprovider;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
// jsr 196 interface types
import javax.security.auth.message.AuthException;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.AuthConfigProvider;
import javax.security.auth.message.config.ClientAuthConfig;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.module.ClientAuthModule;
import javax.security.auth.message.module.ServerAuthModule;

import org.omnifaces.elios.config.data.Entry;
import org.omnifaces.elios.config.data.IDEntry;
import org.omnifaces.elios.config.data.InterceptEntry;
import org.omnifaces.elios.config.data.ModuleInfo;
import org.omnifaces.elios.config.factory.ConfigParser;
import org.omnifaces.elios.config.module.config.GFClientAuthConfig;
import org.omnifaces.elios.config.module.config.GFServerAuthConfig;
import org.omnifaces.elios.services.WebServicesDelegate;

/**
 * This class implements the interface AuthConfigProvider.
 * 
 * @author Shing Wai Chan
 * @author Ronald Monzillo
 */
public class GFServerConfigProvider implements AuthConfigProvider {

    public static final Logger logger = Logger.getLogger(GFServerConfigProvider.class.getName());

    public static final String SOAP = "SOAP";
    public static final String HTTPSERVLET = "HttpServlet";

    protected static final String CLIENT = "client";
    protected static final String SERVER = "server";
    protected static final String MANAGES_SESSIONS_OPTION = "managessessions";

    private static final String DEFAULT_HANDLER_CLASS = "com.sun.enterprise.security.jmac.callback.ContainerCallbackHandler";
    private static final String DEFAULT_PARSER_CLASS = "com.sun.enterprise.security.jmac.config.ConfigDomainParser";

    // since old api does not have subject in PasswordValdiationCallback,
    // this is for old modules to pass group info back to subject
    private static final ThreadLocal<Subject> subjectLocal = new ThreadLocal<Subject>();

    protected static final ReadWriteLock rwLock = new ReentrantReadWriteLock();
    protected static final Map<String, String> layerDefaultRegisIDMap = new HashMap<String, String>();

    // mutable statics should be kept package private to eliminate
    // the ability for subclasses to access them
    static int epoch;
    static String parserClassName = null;
    static ConfigParser parser;
    static boolean parserInitialized = false;
    static AuthConfigFactory slaveFactory = null;

    // keep the slave from being visible outside
    static AuthConfigProvider slaveProvider = null;

    protected AuthConfigFactory factory = null;
    private WebServicesDelegate wsdelegate = null;

    public GFServerConfigProvider(Map properties, AuthConfigFactory factory) {
        this.factory = factory;
        initializeParser();

        if (factory != null) {
            boolean hasSlaveFactory = false;
            try {
                rwLock.readLock().lock();
                hasSlaveFactory = (slaveFactory != null);
            } finally {
                rwLock.readLock().unlock();
            }

            if (!hasSlaveFactory) {
                try {
                    rwLock.writeLock().lock();
                    if (slaveFactory == null) {
                        slaveFactory = factory;
                    }
                } finally {
                    rwLock.writeLock().unlock();
                }
            }
        }

        boolean hasSlaveProvider = false;
        try {
            rwLock.readLock().lock();
            hasSlaveProvider = (slaveProvider != null);
        } finally {
            rwLock.readLock().unlock();
        }

        if (!hasSlaveProvider) {
            try {
                rwLock.writeLock().lock();
                if (slaveProvider == null) {
                    slaveProvider = this;
                }
            } finally {
                rwLock.writeLock().unlock();
            }
        }
    }

    private void initializeParser() {
        try {
            rwLock.readLock().lock();
            if (parserInitialized) {
                return;
            }
        } finally {
            rwLock.readLock().unlock();
        }

        try {
            rwLock.writeLock().lock();
            if (!parserInitialized) {
                parserClassName = System.getProperty("config.parser", DEFAULT_PARSER_CLASS);
                loadParser(this, factory, null);
                parserInitialized = true;
            }
        } finally {
            rwLock.writeLock().unlock();
        }
    }

    /**
     * Instantiate+initialize module class
     */
    static ModuleInfo createModuleInfo(Entry entry, CallbackHandler handler, String type, Map properties) throws AuthException {
        try {
            // instantiate module using no-arg constructor
            Object newModule = entry.newInstance();

            Map map = properties;
            Map entryOptions = entry.getOptions();

            if (entryOptions != null) {
                if (map == null) {
                    map = new HashMap();
                } else {
                    map = new HashMap(map);
                }
                map.putAll(entryOptions);
            }

            // no doPrivilege at this point, need to revisit
            if (SERVER.equals(type)) {
                if (newModule instanceof ServerAuthModule) {
                    ServerAuthModule sam = (ServerAuthModule) newModule;
                    sam.initialize(entry.getRequestPolicy(), entry.getResponsePolicy(), handler, map);
                }
            } else { // CLIENT
                if (newModule instanceof ClientAuthModule) {
                    ClientAuthModule cam = (ClientAuthModule) newModule;
                    cam.initialize(entry.getRequestPolicy(), entry.getResponsePolicy(), handler, map);
                }
            }

            return new ModuleInfo(newModule, map);
        } catch (Exception e) {
            if (e instanceof AuthException) {
                throw (AuthException) e;
            }
            AuthException ae = new AuthException();
            ae.initCause(e);
            throw ae;
        }
    }

    /**
     * Create an object of a given class.
     * 
     * @param className
     *
     */
    private static Object createObject(final String className) {
        final ClassLoader loader = getClassLoader();
        if (System.getSecurityManager() != null) {
            try {
                return AccessController.doPrivileged(new PrivilegedExceptionAction() {
                    public Object run() throws Exception {
                        Class c = Class.forName(className, true, loader);
                        return c.newInstance();
                    }
                });
            } catch (PrivilegedActionException pae) {
                throw new RuntimeException(pae.getException());
            }
        }
        try {
            Class c = Class.forName(className, true, loader);
            return c.newInstance();
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    Entry getEntry(String intercept, String id, MessagePolicy requestPolicy, MessagePolicy responsePolicy, String type) {

        // get the parsed module config and DD information

        Map configMap;

        try {
            rwLock.readLock().lock();
            configMap = parser.getConfigMap();
        } finally {
            rwLock.readLock().unlock();
        }

        if (configMap == null) {
            return null;
        }

        // get the module config info for this intercept

        InterceptEntry intEntry = (InterceptEntry) configMap.get(intercept);
        if (intEntry == null || intEntry.idMap == null) {
            if (logger.isLoggable(Level.FINE)) {
                logger.fine("module config has no IDs configured for [" + intercept + "]");
            }
            return null;
        }

        // look up the DD's provider ID in the module config

        IDEntry idEntry = null;
        if (id == null || (idEntry = (IDEntry) intEntry.idMap.get(id)) == null) {

            // either the DD did not specify a provider ID,
            // or the DD-specified provider ID was not found
            // in the module config.
            //
            // in either case, look for a default ID in the module config

            if (logger.isLoggable(Level.FINE)) {
                logger.fine(
                        "DD did not specify ID, " + "or DD-specified ID for [" + intercept + "] not found in config -- " + "attempting to look for default ID");
            }

            String defaultID;
            if (CLIENT.equals(type)) {
                defaultID = intEntry.defaultClientID;
            } else {
                defaultID = intEntry.defaultServerID;
            }

            idEntry = (IDEntry) intEntry.idMap.get(defaultID);
            if (idEntry == null) {

                // did not find a default provider ID

                if (logger.isLoggable(Level.FINE)) {
                    logger.fine("no default config ID for [" + intercept + "]");
                }
                return null;
            }
        }

        // we found the DD provider ID in the module config
        // or we found a default module config

        // check provider-type
        if (idEntry.type.indexOf(type) < 0) {
            if (logger.isLoggable(Level.FINE)) {
                logger.fine("request type [" + type + "] does not match config type [" + idEntry.type + "]");
            }
            return null;
        }

        // check whether a policy is set
        MessagePolicy reqP = (requestPolicy != null || responsePolicy != null) ? requestPolicy : idEntry.requestPolicy; // default;

        MessagePolicy respP = (requestPolicy != null || responsePolicy != null) ? responsePolicy : idEntry.responsePolicy; // default;

        // optimization: if policy was not set, return null
        if (reqP == null && respP == null) {
            if (logger.isLoggable(Level.FINE)) {
                logger.fine("no policy applies");
            }
            return null;
        }

        // return the configured modules with the correct policies

        Entry entry = new Entry(idEntry.moduleClassName, reqP, respP, idEntry.options);

        if (logger.isLoggable(Level.FINE)) {
            logger.fine("getEntry for: " + intercept + " -- " + id + "\n    module class: " + entry.moduleClassName + "\n    options: " + entry.options
                    + "\n    request policy: " + entry.requestPolicy + "\n    response policy: " + entry.responsePolicy);
        }

        return entry;
    }

    

    /**
     * Get an instance of ClientAuthConfig from this provider.
     *
     * <p>
     * The implementation of this method returns a ClientAuthConfig instance that describes the configuration of
     * ClientAuthModules at a given message layer, and for use in an identified application context.
     *
     * @param layer a String identifying the message layer for the returned ClientAuthConfig object. This argument must not
     * be null.
     *
     * @param appContext a String that identifies the messaging context for the returned ClientAuthConfig object. This
     * argument must not be null.
     *
     * @param handler a CallbackHandler to be passed to the ClientAuthModules encapsulated by ClientAuthContext objects
     * derived from the returned ClientAuthConfig. This argument may be null, in which case the implementation may assign a
     * default handler to the configuration.
     *
     * @return a ClientAuthConfig Object that describes the configuration of ClientAuthModules at the message layer and
     * messaging context identified by the layer and appContext arguments. This method does not return null.
     *
     * @exception AuthException if this provider does not support the assignment of a default CallbackHandler to the
     * returned ClientAuthConfig.
     *
     * @exception SecurityException if the caller does not have permission to retrieve the configuration.
     *
     * The CallbackHandler assigned to the configuration must support the Callback objects required to be supported by the
     * profile of this specification being followed by the messaging runtime. The CallbackHandler instance must be
     * initialized with any application context needed to process the required callbacks on behalf of the corresponding
     * application.
     */
    public ClientAuthConfig getClientAuthConfig(String layer, String appContext, CallbackHandler handler) throws AuthException {
        return new GFClientAuthConfig(this, layer, appContext, handler);
    }

    /**
     * Get an instance of ServerAuthConfig from this provider.
     *
     * <p>
     * The implementation of this method returns a ServerAuthConfig instance that describes the configuration of
     * ServerAuthModules at a given message layer, and for a particular application context.
     *
     * @param layer a String identifying the message layer for the returned ServerAuthConfig object. This argument must not
     * be null.
     *
     * @param appContext a String that identifies the messaging context for the returned ServerAuthConfig object. This
     * argument must not be null.
     *
     * @param handler a CallbackHandler to be passed to the ServerAuthModules encapsulated by ServerAuthContext objects
     * derived from thr returned ServerAuthConfig. This argument may be null, in which case the implementation may assign a
     * default handler to the configuration.
     *
     * @return a ServerAuthConfig Object that describes the configuration of ServerAuthModules at a given message layer, and
     * for a particular application context. This method does not return null.
     *
     * @exception AuthException if this provider does not support the assignment of a default CallbackHandler to the
     * returned ServerAuthConfig.
     *
     * @exception SecurityException if the caller does not have permission to retrieve the configuration.
     * <p>
     * The CallbackHandler assigned to the configuration must support the Callback objects required to be supported by the
     * profile of this specification being followed by the messaging runtime. The CallbackHandler instance must be
     * initialized with any application context needed to process the required callbacks on behalf of the corresponding
     * application.
     */
    public ServerAuthConfig getServerAuthConfig(String layer, String appContext, CallbackHandler handler) throws AuthException {
        return new GFServerAuthConfig(this, layer, appContext, handler);
    }

    /**
     * Causes a dynamic configuration provider to update its internal state such that any resulting change to its state is
     * reflected in the corresponding authentication context configuration objects previously created by the provider within
     * the current process context.
     *
     * @exception AuthException if an error occured during the refresh.
     *
     * @exception SecurityException if the caller does not have permission to refresh the provider.
     */

    public void refresh() {
        loadParser(this, factory, null);
    }

    /**
     * this method is intended to be called by the admin configuration system when the corresponding config object has
     * changed. It relies on the slaves, since it is a static method.
     * 
     * @param config a config object of type understood by the parser. NOTE: there appears to be a thread saftey problem,
     * and this method will fail if a slaveProvider has not been established prior to its call.
     */
    public static void loadConfigContext(Object config) {

        boolean hasSlaveFactory = false;
        boolean hasSlaveProvider = false;
        rwLock.readLock().lock();
        try {
            hasSlaveFactory = (slaveFactory != null);
            hasSlaveProvider = (slaveProvider != null);
        } finally {
            rwLock.readLock().unlock();
        }

        if (slaveProvider == null) {
            if (logger.isLoggable(Level.SEVERE)) {
                logger.severe("unableToLoad.noSlaveProvider");
            }
            return;
        }

        if (!hasSlaveFactory) {
            rwLock.writeLock().lock();
            try {
                if (slaveFactory == null) {
                    slaveFactory = AuthConfigFactory.getFactory();
                }
            } finally {
                rwLock.writeLock().unlock();
            }
        }

        loadParser(slaveProvider, slaveFactory, config);
    }

    protected static void loadParser(AuthConfigProvider aProvider, AuthConfigFactory aFactory, Object config) {
        rwLock.writeLock().lock();
        try {
            ConfigParser nextParser;
            int next = epoch + 1;
            nextParser = (ConfigParser) createObject(parserClassName);
            nextParser.initialize(config);

            if (aFactory != null && aProvider != null) {
                Set<String> layerSet = nextParser.getLayersWithDefault();
                for (String layer : layerDefaultRegisIDMap.keySet()) {
                    if (!layerSet.contains(layer)) {
                        String regisID = layerDefaultRegisIDMap.remove(layer);
                        aFactory.removeRegistration(regisID);
                    }
                }

                for (String layer : layerSet) {
                    if (!layerDefaultRegisIDMap.containsKey(layer)) {
                        String regisID = aFactory.registerConfigProvider(aProvider, layer, null, "GFServerConfigProvider: self registration");
                        layerDefaultRegisIDMap.put(layer, regisID);
                    }
                }
            }
            epoch = (next == 0 ? 1 : next);
            parser = nextParser;
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        } finally {
            rwLock.writeLock().unlock();
        }
    }

    protected static ClassLoader getClassLoader() {
        if (System.getSecurityManager() == null) {
            return Thread.currentThread().getContextClassLoader();
        }

        return (ClassLoader) AccessController.doPrivileged(new PrivilegedAction() {
            public Object run() {
                return Thread.currentThread().getContextClassLoader();
            }
        });
    }

    // for old API
    public static void setValidateRequestSubject(Subject subject) {
        subjectLocal.set(subject);
    }

   

    
}
