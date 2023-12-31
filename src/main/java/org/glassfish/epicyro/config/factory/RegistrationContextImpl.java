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

package org.glassfish.epicyro.config.factory;

import org.glassfish.epicyro.config.factory.file.AuthConfigProviderEntry;
import org.glassfish.epicyro.config.factory.file.RegStoreFileParser;

import jakarta.security.auth.message.config.AuthConfigFactory.RegistrationContext;

/**
 * Class used by {@link BaseAuthConfigFactory}, {@link AuthConfigProviderEntry} and {@link RegStoreFileParser}
 *
 * This class will *not* be used outside of its package.
 */
public final class RegistrationContextImpl implements RegistrationContext {
    private final String messageLayer;
    private final String appContext;
    private final String description;
    private final boolean isPersistent;

    public RegistrationContextImpl(String messageLayer, String appContext, String description, boolean persistent) {
        this.messageLayer = messageLayer;
        this.appContext = appContext;
        this.description = description;
        this.isPersistent = persistent;
    }

    // helper method to create impl class
    public RegistrationContextImpl(RegistrationContext registrationContext) {
        this.messageLayer = registrationContext.getMessageLayer();
        this.appContext = registrationContext.getAppContext();
        this.description = registrationContext.getDescription();
        this.isPersistent = registrationContext.isPersistent();
    }

    @Override
    public String getMessageLayer() {
        return messageLayer;
    }

    @Override
    public String getAppContext() {
        return appContext;
    }

    @Override
    public String getDescription() {
        return description;
    }

    @Override
    public boolean isPersistent() {
        return isPersistent;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || !(o instanceof RegistrationContext)) {
            return false;
        }

        RegistrationContext target = (RegistrationContext) o;

        return (AuthConfigProviderEntry.matchStrings(messageLayer, target.getMessageLayer()) &&
                AuthConfigProviderEntry.matchStrings(appContext, target.getAppContext()) &&
                isPersistent() == target.isPersistent());
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 17 * hash + (this.messageLayer != null ? this.messageLayer.hashCode() : 0);
        hash = 17 * hash + (this.appContext != null ? this.appContext.hashCode() : 0);
        hash = 17 * hash + (this.isPersistent ? 1 : 0);
        return hash;
    }
}
