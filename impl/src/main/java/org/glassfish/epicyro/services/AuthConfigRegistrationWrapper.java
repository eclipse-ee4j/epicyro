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

package org.glassfish.epicyro.services;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import jakarta.security.auth.message.config.AuthConfigFactory;
import jakarta.security.auth.message.config.RegistrationListener;

public class AuthConfigRegistrationWrapper {

    private AuthConfigFactory authConfigFactory;
    private String layer;
    private String applicationContextId;
    private String authenticationProviderRegistrationId;
    private boolean enabled;
    private ConfigData data;

    private Lock wLock;
    private ReadWriteLock rwLock;

    private AuthConfigRegistrationListener listener;
    private int referenceCount = 1;
    private RegistrationWrapperRemover removerDelegate;

    public AuthConfigRegistrationWrapper(AuthConfigFactory authConfigFactory, String layer, String applicationContextId, RegistrationWrapperRemover removerDelegate) {
        this.authConfigFactory = authConfigFactory;
        this.layer = layer;
        this.applicationContextId = applicationContextId;
        this.removerDelegate = removerDelegate;
        this.rwLock = new ReentrantReadWriteLock(true);
        this.wLock = rwLock.writeLock();

        enabled = authConfigFactory != null;
        listener = new AuthConfigRegistrationListener(layer, applicationContextId);
    }

    public AuthConfigRegistrationListener getListener() {
        return listener;
    }

    public void setListener(AuthConfigRegistrationListener listener) {
        this.listener = listener;
    }

    public void disable() {
        this.wLock.lock();

        try {
            setEnabled(false);
        } finally {
            this.wLock.unlock();
            data = null;
        }

        if (authConfigFactory != null) {
            authConfigFactory.detachListener(this.listener, layer, applicationContextId);
            if (getJaspicProviderRegistrationId() != null) {
                authConfigFactory.removeRegistration(getJaspicProviderRegistrationId());
            }
        }
    }

    // Detach the listener, but don't remove-registration
    public void disableWithRefCount() {
        if (referenceCount <= 1) {
            disable();
            if (removerDelegate != null) {
                removerDelegate.removeListener(this);
            }
        } else {
            try {
                this.wLock.lock();
                referenceCount--;
            } finally {
                this.wLock.unlock();
            }

        }
    }

    public void incrementReference() {
        try {
            this.wLock.lock();
            referenceCount++;
        } finally {
            this.wLock.unlock();
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getJaspicProviderRegistrationId() {
        return this.authenticationProviderRegistrationId;
    }

    public void setRegistrationId(String jaspicProviderRegistrationId) {
        this.authenticationProviderRegistrationId = jaspicProviderRegistrationId;
    }

    public ConfigData getConfigData() {
        return data;
    }

    public void setConfigData(ConfigData data) {
        this.data = data;
    }

    public class AuthConfigRegistrationListener implements RegistrationListener {

        private String layer;
        private String appCtxt;

        public AuthConfigRegistrationListener(String layer, String appCtxt) {
            this.layer = layer;
            this.appCtxt = appCtxt;
        }

        @Override
        public void notify(String layer, String appContext) {
            if (this.layer.equals(layer)
                    && ((this.appCtxt == null && appContext == null) || (appContext != null && appContext.equals(this.appCtxt)))) {
                try {
                    wLock.lock();
                    data = null;
                } finally {
                    wLock.unlock();
                }
            }
        }

    }
}