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

import jakarta.security.auth.message.AuthException;
import jakarta.security.auth.message.config.AuthConfigFactory;
import jakarta.security.auth.message.config.AuthConfigFactory.RegistrationContext;
import jakarta.security.auth.message.config.AuthConfigProvider;
import jakarta.security.auth.message.config.RegistrationListener;
import jakarta.security.auth.message.config.ServerAuthConfig;
import jakarta.security.auth.message.config.ServerAuthContext;

import java.io.IOException;
import java.lang.System.Logger;
import java.util.HashMap;
import java.util.Random;
import java.util.StringTokenizer;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.glassfish.epicyro.config.factory.file.AuthConfigFileFactory;
import org.glassfish.epicyro.config.module.configprovider.JAASServletAuthConfigProvider;

import static java.lang.System.Logger.Level.ERROR;
import static java.lang.System.Logger.Level.INFO;

/**
 *
 * @author Ron Monzillo
 */
public class RuntimeSurrogate {

    private static final Logger LOG = System.getLogger(RuntimeSurrogate.class.getName());
    static HashMap<String, String> providerProperties = new HashMap<>();
    AuthConfigFactory factory;
    AuthConfigProvider provider;

    public RuntimeSurrogate(AuthConfigProvider provider, AuthConfigFactory factory) {
        String[] regIDS = factory.getRegistrationIDs(provider);
        for (String i : regIDS) {
            try {
                RegistrationContext r = factory.getRegistrationContext(i);
                System.out.println(contextToString(r));
                AuthConfigProvider p = factory.getConfigProvider(r.getMessageLayer(), r.getAppContext(), null);
                ServerAuthConfig c = p.getServerAuthConfig(r.getMessageLayer(), r.getAppContext(),
                        new CallbackHandler() {

                            @Override
                            public void handle(Callback[] clbcks)
                                    throws IOException, UnsupportedCallbackException {
                                throw new UnsupportedOperationException("Not supported yet.");
                            }
                        });
                ServerAuthContext s = c.getAuthContext("0", new Subject(), new HashMap());
            } catch (AuthException ex) {
                LOG.log(ERROR, "Initialization failed.", ex);
            }
        }
    }

    public final String contextToString(RegistrationContext r) {
        String rvalue = r.getDescription() + "\n\t" + r.getAppContext() + "\n\t"
                + r.getMessageLayer() + "\n\t" + r.isPersistent() + "\n";
        return rvalue;
    }

    public static void main(String[] args) {
        System.out.println("Security Manager is "
                + (System.getSecurityManager() == null ? "OFF" : "ON"));
        System.out.println("user.dir: " + System.getProperty("user.dir"));

        for (String s : args) {
            StringTokenizer tokenizer = new StringTokenizer(s, "=");
            if (tokenizer.countTokens() == 2) {
                String key = tokenizer.nextToken();
                String value = tokenizer.nextToken();
                System.out.println("key: " + key + " value: " + value);
                providerProperties.put(key, value);
            }
        }

        AuthConfigFactory.setFactory(new AuthConfigFileFactory());
        final AuthConfigFactory f = AuthConfigFactory.getFactory();

        final AuthConfigProvider p = new JAASServletAuthConfigProvider(providerProperties, f);
        RuntimeSurrogate rS = new RuntimeSurrogate(p, f);
        /*
        p = new SpringServletAuthConfigProvider(properties, f);
        rS = new RuntimeSurrogate(p, f);
         */
        //listenertest
        RegistrationListener listener =
                new RegistrationListener() {

                    @Override
                    public void notify(String layer, String context) {
                        System.out.println("listener notified - layer: " + layer + " context: " + context);
                        f.getConfigProvider(layer, context, this);
                    }
                };

        String rid1 = f.registerConfigProvider(p, "x", null, "test");
        String rid2 = f.registerConfigProvider(p, "x", "y1", "test");

        f.getConfigProvider("x", "y1", listener);
        f.getConfigProvider("x", "y2", listener);

        f.removeRegistration(rid2);
        f.removeRegistration(rid1);

        providers[0] = null;
        for (int i = 1; i < providers.length; i++) {
            providers[i] = new JAASServletAuthConfigProvider(providerProperties, null);
        }
        f.detachListener(listener, null, null);
        testFactory();
    }
    static AuthConfigProvider[] providers = new AuthConfigProvider[4];
    static final TestThread[] threads = new TestThread[1024];

    public static void testFactory() {

        AuthConfigFactory.setFactory(new AuthConfigFileFactory());

        for (int i = 0; i < threads.length; i++) {
            threads[i] = new TestThread();
        }
        for (TestThread thread : threads) {
            thread.start();
        }
        for (TestThread t : threads) {
            try {
                t.join();
            } catch (InterruptedException ex) {
                LOG.log(ERROR, () -> "thread: " + t.getId() + " caught exception", ex);
            } finally {
                LOG.log(INFO, "thread: {0} completed: {1}", t.getId(), t.runAsConsumer() ? "comsumer" : "producer");
            }
        }
        LOG.log(INFO, "ALL THREADS JOINED");
        AuthConfigFactory f = AuthConfigFactory.getFactory();
        String[] rids = f.getRegistrationIDs(null);
        for (String i : rids) {
            RegistrationContext rc = f.getRegistrationContext(i);
            LOG.log(INFO, "removing registration - layer: {0} appContext: {1} description: {2} persistent: {3}",
                    new Object[]{rc.getMessageLayer(), rc.getAppContext(),
                        rc.getDescription(), rc.isPersistent()});
            f.removeRegistration(i);
        }
        LOG.log(INFO, "ALL REGISTRATIONS REMOVED");
    }

    static class TestThread extends Thread implements RegistrationListener {

        static Random random = new Random();
        static String[] layers = new String[4];
        static String[] contexts = new String[16];
        static int consumerCount = threads.length;
        boolean runAsConsumer = false;
        boolean stop;

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

        @Override
        public void run() {
            synchronized (TestThread.class) {
                if (consumerCount == threads.length) {
                    runAsConsumer = false;
                } else {
                    runAsConsumer = (random.nextInt(threads.length / 10) != 1);
                }
            }
            AuthConfigFactory f = AuthConfigFactory.getFactory();
            if (runAsConsumer) {
                doConsumer(f, layers[random.nextInt(layers.length)], contexts[random.nextInt(contexts.length)]);
            } else {
                synchronized (TestThread.class) {
                    consumerCount--;
                    LOG.log(INFO, "creating producer, remaining consumers: {0}", consumerCount);
                }
                while (true) {
                    synchronized (TestThread.class) {
                        if (consumerCount == 0) {
                            return;
                        }
                    }
                    switch (random.nextInt(5)) {
                        case 0:
                            if (random.nextInt(25) == 1) {
                                try {
                                    f.refresh();
                                } catch (Exception e) {
                                    LOG.log(ERROR, "producer thread: " + getId(), e);
                                }
                            }
                            break;
                        case 1:
                            if (random.nextInt(1000) == 1) {
                                try {
                                    f = AuthConfigFactory.getFactory();
                                    AuthConfigFactory.setFactory(f);
                                } catch (Exception e) {
                                    LOG.log(ERROR, "producer thread: " + getId(), e);
                                }
                            }
                            break;
                        case 2:
                            try {
                                f.registerConfigProvider(
                                        "servlet.JAASServletAuthConfigProvider", providerProperties,
                                        layers[random.nextInt(layers.length)],
                                        contexts[random.nextInt(contexts.length)],
                                        "persistent registration");
                            } catch (Exception e) {
                                LOG.log(ERROR, "producer thread: " + getId(), e);
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
                                LOG.log(ERROR, "producer thread: " + getId(), e);
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
                                LOG.log(ERROR, "producer thread: " + getId(), e);
                            }
                            break;

                    }
                }
            }
        }

        public boolean runAsConsumer() {
            return runAsConsumer;
        }

        public void doConsumer(AuthConfigFactory f, String layer, String context) {

            synchronized (TestThread.class) {
                LOG.log(INFO, "creating consumer");
                this.stop = false;
            }
            try {
                while (true) {
                    f.getConfigProvider(layer, context, this);
                    sleep(100);
                    synchronized (TestThread.class) {
                        if (this.stop) {
                            break;
                        }
                    }
                }
                f.detachListener(this, null, null);
            } catch (Exception e) {
                LOG.log(ERROR, () -> "consumer thread: " + getId(), e);
            } finally {
                synchronized (TestThread.class) {
                    consumerCount--;
                    LOG.log(INFO, "consumer thread: {0} stopping - remaining: {1}", getId(), consumerCount);
                }
            }
        }

        @Override
        public void notify(String layer, String context) {
            if (random.nextInt(100) == 1) {
                synchronized (TestThread.class) {
                    this.stop = true;
                }
            }
        }
    }
}
