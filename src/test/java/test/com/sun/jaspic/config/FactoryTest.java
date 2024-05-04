/*
 * Copyright (c) 2024 OmniFish and/or its affiliates. All rights reserved.
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

package test.com.sun.jaspic.config;

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.ERROR;
import static java.lang.System.Logger.Level.INFO;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import jakarta.security.auth.message.AuthException;
import jakarta.security.auth.message.MessageInfo;
import jakarta.security.auth.message.config.AuthConfigFactory;
import jakarta.security.auth.message.config.AuthConfigFactory.RegistrationContext;
import jakarta.security.auth.message.config.AuthConfigProvider;
import jakarta.security.auth.message.config.ClientAuthConfig;
import jakarta.security.auth.message.config.ClientAuthContext;
import jakarta.security.auth.message.config.RegistrationListener;
import jakarta.security.auth.message.config.ServerAuthConfig;
import jakarta.security.auth.message.config.ServerAuthContext;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.StringTokenizer;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import org.glassfish.epicyro.config.factory.BaseAuthConfigFactory;
import org.glassfish.epicyro.config.factory.file.AuthConfigFileFactory;
import org.glassfish.epicyro.config.factory.file.AuthConfigProviderEntry;
import org.glassfish.epicyro.config.factory.file.RegStoreFileParser;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Ron Monzillo
 */
public class FactoryTest {

    /** switch definition of default test factory to test native factory
     * will also need to configure proper dependencies
     */
    // private static final String DEFAULT_TEST_FACTORY_CLASS_NAME = "com.sun.enterprise.security.jmac.config.SaveAuthConfigFactory";
    private static final String DEFAULT_TEST_FACTORY_CLASS_NAME = AuthConfigFileFactory.class.getName();
    private static String testFactoryClassName = DEFAULT_TEST_FACTORY_CLASS_NAME;
    public static final String DEFAULT_FACTORY_SECURITY_PROPERTY =
            "authconfigprovider.factory";
    public static final String USER_DIR_PROPERTY = "user.dir";
    static final String THREAD_COUNT_KEY = "test.thread.count";
    static final String MAX_JOIN_SECONDS_KEY = "test.max.join.seconds";
    static final String TEST_FACTORY_CLASS_NAME_KEY = "test.factory.class.name";
    static final int DEFAULT_THREAD_COUNT = 32;
    static final int DEFAULT_MAX_JOIN_SECONDS = 600;

    private static final Logger LOG = System.getLogger(FactoryTest.class.getName());

    private static String defaultFactoryClassName;
    private static AuthConfigFactory testFactory;
    static HashMap<String, String> options = new HashMap<>();
    private static ExecutorService threadPool;
    static int consumerCount;
    static int activeConsumers;
    static Random random = new Random();
    static final String[] layers = new String[4];
    static final String[] contexts = new String[16];

    static {
        layers[0] = null;
        for (int i = 1; i < layers.length; i++) {
            layers[i] = "layer" + Integer.toString(i);
        }
        contexts[0] = null;
        for (int i = 1; i < contexts.length; i++) {
            contexts[i] = "context" + Integer.toString(i);
        }
    }
    static AuthConfigProvider[] providers = new AuthConfigProvider[4];

    public FactoryTest() {
    }

    public static String getStringOption(String key, String defaultValue) {
        String s = options == null ? null : (String) options.get(key);
        if (s == null) {
            return defaultValue;
        }
        return s;
    }

    public static int getIntOption(String key, int defaultValue) {
        String s = options == null ? null : (String) options.get(key);
        if (s == null) {
            return defaultValue;
        }
        return Integer.parseInt(s);
    }

    public static boolean getbooleanOption(String key, boolean defaultValue) {
        String s = options == null ? null : (String) options.get(key);
        if (s == null) {
            return defaultValue;
        }
        return Boolean.parseBoolean(s);
    }

    public static String[] splitStringOption(String s) {
        if (s == null) {
            return new String[0];
        }
        return s.split(",|:| |;");
    }

    static Map<String, String> getProviderProperties() {
        return new HashMap<>();
    }

    static AuthConfigFactory loadFactory(final String className) {
        AuthConfigFactory factory = null;
        try {
            factory = (AuthConfigFactory)
                Class.forName(className, true, Thread.currentThread().getContextClassLoader())
                     .getDeclaredConstructor()
                     .newInstance();
        } catch (ReflectiveOperationException pae) {
            throw new SecurityException(pae);
        } finally {
            assertNotNull("loadFactory returned null", factory);
        }

        return factory;
    }

    public static void main(String[] args) {

        for (String s : args) {
            StringTokenizer tokenizer = new StringTokenizer(s, "=");
            if (tokenizer.countTokens() == 2) {
                String key = tokenizer.nextToken();
                String value = tokenizer.nextToken();
                System.out.println("key: " + key + " value: " + value);
                options.put(key, value);
            }
        }

        testFactoryClassName = getStringOption(TEST_FACTORY_CLASS_NAME_KEY,
                DEFAULT_TEST_FACTORY_CLASS_NAME);

        new FactoryTest().beforeTest();
        new FactoryTest().testSetFactory();
        new FactoryTest().afterTest();

        new FactoryTest().beforeTest();
        new FactoryTest().testOverrideForDefaultEntries();
        new FactoryTest().afterTest();

        new FactoryTest().beforeTest();
        new FactoryTest().testRemoveRegistration();
        new FactoryTest().afterTest();

        new FactoryTest().beforeTest();
        new FactoryTest().testListeners();
        new FactoryTest().afterTest();

        new FactoryTest().beforeTest();
        new FactoryTest().stressFactory(
                getIntOption(THREAD_COUNT_KEY, DEFAULT_THREAD_COUNT),
                getIntOption(MAX_JOIN_SECONDS_KEY, DEFAULT_MAX_JOIN_SECONDS));
        new FactoryTest().afterTest();

        new FactoryTest().beforeTest();
        new FactoryTest().testRegistrationWithNonStringProperty();
        new FactoryTest().afterTest();

        new FactoryTest().beforeTest();
        new FactoryTest().testRegistrationWithNonStringPropertyAndPreviousRegistration();
        new FactoryTest().afterTest();
    }

	@Before
    public void beforeTest() {
        try {
            defaultFactoryClassName = Security.getProperty(DEFAULT_FACTORY_SECURITY_PROPERTY);
            LOG.log(INFO, "\n\tSecurity Manager is {0}\n\t{1} is {2}\n\t{3} is {4}\n\t{5} is {6}\n",
                        (System.getSecurityManager() == null ? "OFF" : "ON"),
                        DEFAULT_FACTORY_SECURITY_PROPERTY, defaultFactoryClassName,
                        "Test Factory Class Name", testFactoryClassName,
                        USER_DIR_PROPERTY, System.getProperty(USER_DIR_PROPERTY));
            testFactory = loadFactory(testFactoryClassName);
            AuthConfigFactory.setFactory(testFactory);
        } catch (Throwable t) {
            LOG.log(ERROR, "Exception in test setup", t);
            fail("exception in test setup: " + t.toString());
        }
        assertNotNull("at exit of beforeTest getFactory returns null",AuthConfigFactory.getFactory());
    }

    @After
    public void afterTest() {
        AuthConfigFactory.setFactory(null);
    }

    @Test
    public void testSetFactory() {
        LOG.log(INFO, "BEGIN Set FACTORY TEST");
        AuthConfigFactory.setFactory(null);
        assertTrue(defaultFactoryClassName == null
                ? AuthConfigFactory.getFactory() == null
                : defaultFactoryClassName.equals(AuthConfigFactory.getFactory().getClass().getName()));
        if (defaultFactoryClassName != null) {
            Security.setProperty(DEFAULT_FACTORY_SECURITY_PROPERTY, testFactoryClassName);
            AuthConfigFactory.setFactory(null);
            assertTrue(testFactoryClassName.equals(AuthConfigFactory.getFactory().getClass().getName()));
            Security.setProperty(DEFAULT_FACTORY_SECURITY_PROPERTY, defaultFactoryClassName);
            AuthConfigFactory.setFactory(null);
            assertTrue(defaultFactoryClassName.equals(AuthConfigFactory.getFactory().getClass().getName()));
        }
        AuthConfigFactory.setFactory(testFactory);
        assertTrue(testFactoryClassName.equals(AuthConfigFactory.getFactory().getClass().getName()));
    }

    @Test
    public void testRegistrationWithNonStringProperty() {
        LOG.log(INFO, "BEGIN Registration with NonString Property FACTORY TEST");
        Security.setProperty(DEFAULT_FACTORY_SECURITY_PROPERTY, testFactoryClassName);
        String className = _AuthConfigProvider.class.getName();
        HashMap properties = new HashMap();
        ArrayList list = new ArrayList();
        list.add("larry was here");
        properties.put("test", list);
        String layer = "HttpServlet";
        String appContext = "context";
        String description = null;
        String regId = null;
        try {
        	regId = AuthConfigFactory.getFactory().registerConfigProvider(className, properties, layer, appContext, description);
        } catch (IllegalArgumentException iae) {
            assertNull("Failed Registration Should Have Resulted in a NULL RegistrationID returned but did not.", regId);
        }
        AuthConfigProvider acp = null;
    	acp = AuthConfigFactory.getFactory().getConfigProvider(layer, appContext, null);
        assertNull("Registration Should Have Failed and Therefore No ACP Should Have been Found.", acp);
    }

    @Test
    public void testRegistrationWithNonStringPropertyAndPreviousRegistration() {
        LOG.log(INFO, "BEGIN Registration with NonString Property and Previous Registration FACTORY TEST");
        Security.setProperty(DEFAULT_FACTORY_SECURITY_PROPERTY, testFactoryClassName);

        // first register a valid acp configuration
        String className = _AuthConfigProvider.class.getName();
        HashMap properties = null;
        String layer = "HttpServlet";
        String appContext = "context";
        String description = null;
        String regId = null;
    	regId = AuthConfigFactory.getFactory().registerConfigProvider(className, properties, layer, appContext, description);
    	assertNotNull("Registration Should Have Succeeded returning a nonNULL RegistrationID but did not.", regId);
        AuthConfigProvider previousAcp = null;
        previousAcp = AuthConfigFactory.getFactory().getConfigProvider(layer, appContext, null);
    	assertNotNull("Registration Should Have Succeeded returning a nonNULL ACP but did not.", previousAcp);
    	String previousRegId = regId;

        // now for an invalid configuration
        properties = new HashMap();
        ArrayList list = new ArrayList();
        list.add("larry was here");
        properties.put("test", list);
        layer = "HttpServlet";
        appContext = "context";
        description = null;
        regId = null;
        try {
        	regId = AuthConfigFactory.getFactory().registerConfigProvider(className, properties, layer, appContext, description);
        } catch (IllegalArgumentException iae) {
            assertNull("Failed Registration Should Have Resulted in a NULL RegistrationID returned but did not.", regId);
        }
        AuthConfigProvider acp = null;
    	acp = AuthConfigFactory.getFactory().getConfigProvider(layer, appContext, null);
        assertTrue("Registration Should Have Failed for Invalid Config and Therefore returned the Previously Registered ACP", previousAcp == acp);

        assertTrue("Failed to remove the previously registered provider.", AuthConfigFactory.getFactory().removeRegistration(previousRegId));
    }

    @Test
    public void testOverrideForDefaultEntries() {
        LOG.log(INFO, "BEGIN overrideGetDefaultEntries TEST");
        AuthConfigFactory f = new _ExtendsBaseAuthConfigFactory();
        f = new _Extends_ExtendsAuthConfigFactory();
    }

    static class _ExtendsBaseAuthConfigFactory extends BaseAuthConfigFactory {

        // regStore MUST hide regStore of bade class
        private static RegStoreFileParser regStore = null;

        /**
         * To specialize the defaultEntries passed to the RegStoreFileParser,
         * construct EntryInfo objects within this constructor.
         * THE EentyInfo OBJECTS MUST ONLY BE CONSTRCTED USING THE FOLLOWING
         * CONSTRUCTOR: EntryInfo(String className, Map<String, String> properties)
         * NO Entries are passed by this test, because to do so, the parent
         * test class would need to import EntryInfo (which it can't).
         */
        public _ExtendsBaseAuthConfigFactory() {
            ////rLock.lock();
            try {
                if (regStore != null) {
                    return;
                }
            } finally {
                //rLock.unlock();
            }
            String userDir = System.getProperty("user.dir");
            //wLock.lock();
            try {
                if (regStore == null) {
                    AuthConfigProviderEntry e = new AuthConfigProviderEntry(_AuthConfigProvider.class.getName(),null);
                    List<AuthConfigProviderEntry> defaultEntries = new ArrayList<>();
                    defaultEntries.add(e);
                    regStore = new RegStoreFileParser(userDir,
                            BaseAuthConfigFactory.CONF_FILE_NAME,defaultEntries);
                    _loadFactory();
                }
            } finally {
                //wLock.unlock();
            }
            RegStoreFileParser rS = getRegStore();
            assertTrue(rS == _ExtendsBaseAuthConfigFactory.regStore);
        }

        @Override
        protected RegStoreFileParser getRegStore() {
            ////rLock.lock();
            try {
                return regStore;
            } finally {
                //rLock.unlock();
            }
        }
    }

    static class _Extends_ExtendsAuthConfigFactory extends _ExtendsBaseAuthConfigFactory {

        // regStore MUST hide regStore of base class
        private static RegStoreFileParser regStore = null;

        /**
         * To specialize the defaultEntries passed to the RegStoreFileParser,
         * construct EntryInfo objects within this constructor.
         * THE EentyInfo OBJECTS MUST ONLY BE CONSTRCTED USING THE FOLLOWING
         * CONSTRUCTOR: EntryInfo(String className, Map<String, String> properties)
         * NO Entries are passed by this test, because to do so, the parent
         * test class would need to import EntryInfo (which it can't).
         */
        public _Extends_ExtendsAuthConfigFactory() {
            ////rLock.lock();
            try {
                if (regStore != null) {
                    return;
                }
            } finally {
                //rLock.unlock();
            }
            String userDir = System.getProperty("user.dir");
            //wLock.lock();
            try {
                if (regStore == null) {
                    AuthConfigProviderEntry e = new AuthConfigProviderEntry(_AuthConfigProvider.class.getName(),null);
                    List<AuthConfigProviderEntry> defaultEntries = new ArrayList<>();
                    defaultEntries.add(e);
                    regStore = new RegStoreFileParser(userDir,
                            BaseAuthConfigFactory.CONF_FILE_NAME,defaultEntries);
                    _loadFactory();
                }
            } finally {
                //wLock.unlock();
            }
            RegStoreFileParser rS = getRegStore();
            assertTrue(rS == _Extends_ExtendsAuthConfigFactory.regStore);
        }

        @Override
        protected RegStoreFileParser getRegStore() {
            //rLock.lock();
            try {
                return regStore;
            } finally {
                //rLock.unlock();
            }
        }
    }

    @Test
    public void testRemoveRegistration() {
        LOG.log(INFO, "BEGIN Remove Registration TEST");
        final AuthConfigFactory f = AuthConfigFactory.getFactory();
        f.refresh();
        // does self registration
        AuthConfigProvider p = new _AuthConfigProvider(new HashMap(), f);
        RegistrationContext rc;
        String[] rids = f.getRegistrationIDs(p);
        boolean removed;
        assertTrue("provider did not self register", rids != null && rids.length > 0);
        for (String i : rids) {
            rc = f.getRegistrationContext(i);
            removed = f.removeRegistration(i);
            assertTrue("expected true from removeRegistration - rid: " + i,
                    rc != null && removed);
        }
        for (String i : rids) {
            rc = f.getRegistrationContext(i);
            removed = f.removeRegistration(i);
            assertTrue("expected false from removeRegistration - rid: " + i,
                    rc == null && !removed);
        }

        //testing registration and removal of null provider;
        String rid = f.registerConfigProvider(null, null, null, "null registration");
        rc = f.getRegistrationContext(rid);
        removed = f.removeRegistration(rid);
        assertTrue("testing null provider - expected true from removeRegistration - rid: " + rid,
                rc != null && removed);
        //testing for interferece with null provider
        rc = f.getRegistrationContext(rid);
        removed = f.removeRegistration(rid);
        assertTrue("testing null provider - expected false from removeRegistration - rid: " + rid,
                rc == null && !removed);
        rid = f.registerConfigProvider(null, null, null, "null registration");
        //temporary to force call to decomposeRegId in getEffectedListeners
        p = f.getConfigProvider(null, null, new _Listener(null, null, false));
        rc = f.getRegistrationContext(rid);
        assertTrue("testing null provider - getRegistrationContext - rid: " + rid,
                rid != null);
        String badRid = "someInvalidId";
        rc = f.getRegistrationContext(badRid);
        removed = f.removeRegistration(badRid);
        assertTrue("expected false from removeRegistration - rid: " + badRid,
                rc == null && !removed);
        rc = f.getRegistrationContext(rid);
        removed = f.removeRegistration(rid);
        assertTrue("testing null provider - expected true from removeRegistration - rid: " + rid,
                rc != null && removed);
    }

    @Test
    public void testListeners() {
        LOG.log(INFO, "BEGIN Listener TEST");
        final AuthConfigFactory f = AuthConfigFactory.getFactory();
        final AuthConfigProvider p = new _AuthConfigProvider(new HashMap(), null);

        String layer[] = {null, "11", "l2"};
        String context[] = {null, "c1", "c2"};
        String rid[] = new String[(layer.length - 1) * (context.length - 1)];
        String ridLayer[] = new String[rid.length];
        String ridContext[] = new String[rid.length];

        int z = 0;
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 2; j++) {
                ridLayer[z] = layer[i];
                ridContext[z] = context[j];
                rid[z] = f.registerConfigProvider(p, ridLayer[z], ridContext[z],
                        ridLayer[z] + ridContext[z]);
                z++;
            }
        }

        _Listener listener[] = new _Listener[rid.length];

        z = 0;
        for (int i = 1; i < layer.length; i++) {
            for (int j = 1; j < context.length; j++) {
                listener[z] = new _Listener(layer[i], context[j], true);
                f.getConfigProvider(layer[i], context[j], listener[z]);
                z++;
            }
        }

        for (String element : rid) {
            f.removeRegistration(element);
        }


        f.detachListener(listener[0], null, null);
        f.detachListener(listener[1], listener[1].getLayer(), null);
        f.detachListener(listener[2], null, listener[2].getAppContext());
        f.detachListener(listener[3], listener[3].getLayer(), listener[3].getAppContext());

        //should not find any left to detach
        for (_Listener element : listener) {
            f.detachListener(element, element.getLayer(), element.getAppContext());
        }

        for (int i = 0; i < rid.length; i++) {
            rid[i] = f.registerConfigProvider(p, ridLayer[i], ridContext[i], ridLayer[i] + ridContext[i]);
        }

        z = 0;
        for (int i = 1; i < layer.length; i++) {
            for (int j = 1; j < context.length; j++) {
                listener[z] = new _Listener(layer[i], context[j], false);
                f.getConfigProvider(layer[i], context[j], listener[z]);
                z++;
            }
        }
        for (int i = 0; i < rid.length; i++) {
            for (_Listener element : listener) {
                if (element.notified) {
                    assertTrue("Test Setup Failure - listener could not be registered",
                            element.register());
                }
            }
            f.removeRegistration(rid[i]);

            for (_Listener element : listener) {
                element.check(ridLayer[i], ridContext[i]);
            }
        }

        //repeat with null provider registrations
        for (int i = 0; i < rid.length; i++) {
            rid[i] = f.registerConfigProvider(null, ridLayer[i], ridContext[i], ridLayer[i] + ridContext[i]);
        }

        z = 0;
        for (int i = 1; i < layer.length; i++) {
            for (int j = 1; j < context.length; j++) {
                listener[z] = new _Listener(layer[i], context[j], false);
                f.getConfigProvider(layer[i], context[j], listener[z]);
                z++;
            }
        }
        for (int i = 0; i < rid.length; i++) {
            for (_Listener element : listener) {
                if (element.notified) {
                    assertTrue("Test Setup Failure - listener could not be registered",
                            element.register());
                }
            }
            f.removeRegistration(rid[i]);

            for (_Listener element : listener) {
                element.check(ridLayer[i], ridContext[i]);
            }
        }
    }

    static class _Listener implements RegistrationListener {

        String layer;
        String appContext;
        boolean reRegister;
        boolean notified;

        _Listener(String layer, String appContext, boolean reRegister) {
            this.layer = layer;
            this.appContext = appContext;
            this.reRegister = reRegister;
            this.notified = false;
        }

        String getLayer() {
            return layer;
        }

        String getAppContext() {
            return appContext;
        }

        synchronized boolean register() {
            boolean rvalue = false;
            if (notified) {
                notified = false;
                rvalue = true;
                AuthConfigFactory.getFactory().getConfigProvider(layer, appContext, this);
            }
            return rvalue;
        }

        synchronized boolean notified() {
            return notified;
        }

        void check(String l, String c) {
            boolean shouldHaveBeenNotified = false;
            if ((l == null || layer.equals(l)) && (c == null || appContext.equals(c))) {
                shouldHaveBeenNotified = true;
            }
            if (shouldHaveBeenNotified) {
                String msg = "listener at layer,context: " + layer + "," + appContext + " should have been notified at: "
                        + l + "," + c;
                assertTrue(msg, notified());
            } else {
                String msg = "listener at layer,context: " + layer + "," + appContext + " should NOT have been notified at: "
                        + l + "," + c;
                assertFalse(msg, notified());
            }
        }

        @Override
        public void notify(String l, String c) {
            synchronized (this) {
                notified = true;
            }
            boolean validNotification = (layer == l || layer.equals(l))
                    && (appContext == c || appContext.equals(c));
            String msg = "listener notified at wrong layer: " + l + " or context: " + c;
            assertTrue(msg, validNotification);
            if (validNotification && reRegister) {
                register();
            }
        }
    }

    @Test
    public void stressFactory() {
        stressFactory(DEFAULT_THREAD_COUNT, DEFAULT_MAX_JOIN_SECONDS);
    }

    public void stressFactory(int threadCount, int maxJoinSeconds) {

        LOG.log(INFO, "BEGIN stress FACTORY TEST");
        AuthConfigFactory f = AuthConfigFactory.getFactory();
        f.refresh();
        providers[0] = null;

        for (int i = 1; i < providers.length; i++) {
            providers[i] = new _AuthConfigProvider(getProviderProperties(), null);
        }
        threadPool =  Executors.newFixedThreadPool(threadCount);
        synchronized (_Thread.class) {
            activeConsumers = threadCount;
            consumerCount = threadCount;
        }

        ArrayList<Callable<_ResultCarrier>> tasks = new ArrayList<>();

        for (int i = 0; i < threadCount; i++) {
            _ResultCarrier carrier = new _ResultCarrier();
            Callable<_ResultCarrier> task =
                    Executors.callable(new _Thread(threadCount,carrier),carrier);
            tasks.add(task);
        }

        LOG.log(INFO, "STARTING {0} THREADS", threadCount);
        try {
            List<Future<_ResultCarrier>> futures = threadPool.invokeAll(tasks,maxJoinSeconds,TimeUnit.SECONDS);
            for (Future<_ResultCarrier> future : futures) {
                if (future.isCancelled()) {
                    LOG.log(Level.WARNING,
                        "try increasing maxJoinSeconds in {0}: test aborted because it did not terminate in {1} seconds",
                        new Object[]{this.getClass().getName(),maxJoinSeconds});
                    fail("test did not terminate in: " + maxJoinSeconds + " seconds");
                } else if (future.isDone()) {
                    String errorMessage = future.get().getResult();
                    if (errorMessage != null) {
                        LOG.log(Level.ERROR, errorMessage);
                        fail(errorMessage);
                    }
                }
            }
        } catch (Throwable t) {
            String exceptionMessage = "exception from invoking tasks or from invoked task";
            LOG.log(Level.ERROR, exceptionMessage,t);
            fail(exceptionMessage + t.toString());
        }

        synchronized (_Thread.class) {
            LOG.log(INFO, "ALL THREADS JOINED - producers: {0} consumers: {1}",
                    new Object[]{threadCount - consumerCount, consumerCount});
        }

        String[] rids = f.getRegistrationIDs(null);
        for (String i : rids) {
            RegistrationContext rc = f.getRegistrationContext(i);
            f.removeRegistration(i);
        }
        LOG.log(INFO, "ALL REGISTRATIONS REMOVED");

        f.refresh();
    }

    static class _ResultCarrier {
        String result;
        synchronized String getResult() {
            return result;
        }
        synchronized void setResult(String result) {
            this.result = result;
        }
    }

    static class _Thread extends Thread implements RegistrationListener {

        _ResultCarrier resultCarrier;
        boolean runAsConsumer;
        boolean stop;

        _Thread(int threadCount, _ResultCarrier carrier) {
            this.resultCarrier = carrier;
            synchronized (_Thread.class) {
                if (consumerCount == threadCount) {
                    runAsConsumer = false;
                } else {
                    runAsConsumer = (random.nextInt(10) != 1);
                }
                if (!runAsConsumer) {
                    consumerCount--;
                    activeConsumers--;
                    LOG.log(DEBUG, "creating producer, remaining consumers: {0}", consumerCount);
                }
            }
            setResult(null);
            stop = false;
        }

        private void setResult(String result) {
            resultCarrier.setResult(result);
        }

        @Override
        public void run() {
            AuthConfigFactory f = AuthConfigFactory.getFactory();
            if (f == null) {
                String msg = "new thread: " + getId() + " found null factory";
                LOG.log(ERROR, msg);
                setResult(msg);
            }
            else if (runAsConsumer) {
                doConsumer(f, layers[random.nextInt(layers.length)],
                            contexts[random.nextInt(contexts.length)]);
            } else {
                while (true) {

                    synchronized (_Thread.class) {
                        if (activeConsumers == 0) {
                            setResult(null);
                            return;
                        }
                    }

                    switch (random.nextInt(5)) {
                        case 0:
                            if (random.nextInt(25) == 1) {
                                try {
                                    f.refresh();
                                } catch (Exception e) {
                                    String msg = "producer thread(refresh): " + getId() + " caught exception: ";
                                    LOG.log(ERROR, msg, e);
                                    setResult(msg + e.toString());
                                    return;
                                }
                            }
                            break;
                        case 1:
                            if (random.nextInt(1000) == 1) {
                                try {
                                    f = AuthConfigFactory.getFactory();
                                    if (f == null) {
                                        String msg = "producer thread(get/set): " + getId() + " found null factory";
                                        LOG.log(ERROR, msg);
                                        setResult(msg);
                                        return;
                                    }
                                    AuthConfigFactory.setFactory(f);
                                } catch (Exception e) {
                                    String msg = "producer thread(get/setFactory): " + getId() + " caught exception: ";
                                    LOG.log(ERROR, msg, e);
                                    setResult(msg + e.toString());
                                    return;
                                }
                            }
                            break;
                        case 2:
                            try {
                                f.registerConfigProvider(
                                        _AuthConfigProvider.class.getName(),
                                        getProviderProperties(),
                                        layers[random.nextInt(layers.length)],
                                        contexts[random.nextInt(contexts.length)],
                                        "persistent registration");
                            } catch (Exception e) {
                                String msg = "producer thread(register persistent): " + getId() + " caught exception: ";
                                LOG.log(ERROR, msg, e);
                                setResult(msg + e.toString());
                                return;
                            }
                            break;
                        case 3:
                            try {
                                f.registerConfigProvider(
                                        providers[random.nextInt(providers.length)],
                                        layers[random.nextInt(layers.length)],
                                        contexts[random.nextInt(contexts.length)],
                                        "transient registration");
                            } catch (Exception e) {
                                String msg = "producer thread(register transient): " + getId() + " caught exception: ";
                                LOG.log(ERROR, msg, e);
                                setResult(msg + e.toString());
                                return;
                            }
                            break;
                        case 4:
                            try {
                                String[] rids = f.getRegistrationIDs(
                                        providers[random.nextInt(providers.length)]);
                                int length = rids.length;
                                boolean removeNext = true;
                                for (String rid : rids) {
                                    RegistrationContext rc = f.getRegistrationContext(rid);
                                    if (rc == null) {
                                        removeNext = true;
                                    } else if (removeNext) {
                                        f.removeRegistration(rid);
                                        removeNext = false;
                                    } else {
                                        removeNext = true;
                                    }
                                }
                            } catch (Exception e) {
                                String msg = "producer thread(remove registration): " + getId() + " caught exception: ";
                                LOG.log(ERROR, msg, e);
                                setResult(msg + e.toString());
                                return;

                            }
                            break;

                        }
                    }
            }
        }

        public void doConsumer(AuthConfigFactory f, String layer, String context) {

            String msg = null;

            synchronized (_Thread.class) {
                LOG.log(DEBUG, "creating consumer");
                this.stop = false;
            }

            try {
                f.getConfigProvider(layer, context, this);
                while (true) {
                    sleep(10);
                    synchronized (_Thread.class) {
                        if (this.stop) {
                           break;
                        }
                    }
                }
                f.detachListener(this, null, null);
            } catch (Exception e) {
                msg = "consumer thread: "  + getId() + " caught exception";
                LOG.log(ERROR, msg, e);
                setResult(msg + e.toString());
            } finally {
                synchronized (_Thread.class) {
                    activeConsumers--;
                    LOG.log(INFO, "consumer thread: {0} stopping - remaining: {1}",
                            new Object[]{getId(), activeConsumers});
                }
            }
        }

        @Override
        public void notify(String layer, String context) {
            if (random.nextInt(100) == 1) {
                synchronized (_Thread.class) {
                    setResult(null);
                    this.stop = true;
                }
            } else {
                AuthConfigFactory factory = AuthConfigFactory.getFactory();
                if (factory != null) {
                    factory.getConfigProvider(layer, context, this);
                } else {
                    synchronized (_Thread.class) {
                        setResult("factory is null in notify call on consumer");
                        this.stop = true;
                    }
                }
            }
        }
    }


    public static class _AuthConfigProvider implements AuthConfigProvider {

        public _AuthConfigProvider(Map<String, String> properties, AuthConfigFactory f) {
            if (f != null) {
                f.registerConfigProvider(this,
                        layers[random.nextInt(layers.length)],
                        contexts[random.nextInt(contexts.length)],
                        "self registration");
            }
        }

        @Override
        public ClientAuthConfig getClientAuthConfig(final String layer,
                final String appCtxt, CallbackHandler ch) throws AuthException {

            return new ClientAuthConfig() {

                @Override
                public ClientAuthContext getAuthContext(String string, Subject sbjct, Map map) throws AuthException {
                    throw new UnsupportedOperationException();
                }

                @Override
                public String getMessageLayer() {
                    return layer;
                }

                @Override
                public String getAppContext() {
                    return appCtxt;
                }

                @Override
                public String getAuthContextID(MessageInfo mi) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public void refresh() {
                }

                @Override
                public boolean isProtected() {
                    throw new UnsupportedOperationException();
                }
            };
        }

        @Override
        public ServerAuthConfig getServerAuthConfig(final String layer,
                final String appCtxt, CallbackHandler ch) throws AuthException {

            return new ServerAuthConfig() {

                @Override
                public ServerAuthContext getAuthContext(String string, Subject sbjct, Map map) throws AuthException {
                    throw new UnsupportedOperationException();
                }

                @Override
                public String getMessageLayer() {
                    return layer;
                }

                @Override
                public String getAppContext() {
                    return appCtxt;
                }

                @Override
                public String getAuthContextID(MessageInfo mi) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public void refresh() {
                }

                @Override
                public boolean isProtected() {
                    throw new UnsupportedOperationException();
                }
            };
        }

        @Override
        public void refresh() {
        }
    }



}
