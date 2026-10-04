/*
 * Copyright (c) 2026 Contributors to the Eclipse Foundation.
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
package org.glassfish.epicyro.quarkus.runtime;

import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;

import java.util.Optional;

import static io.quarkus.runtime.annotations.ConfigPhase.BUILD_AND_RUN_TIME_FIXED;

/**
 * Jakarta Authentication (Epicyro) configuration.
 */
@ConfigMapping(prefix = "quarkus.epicyro")
@ConfigRoot(phase = BUILD_AND_RUN_TIME_FIXED)
public interface EpicyroConfig {

    /**
     * The virtual server name of the servlet deployment, as returned by {@code ServletContext#getVirtualServerName()}.
     * It is the first part of the Jakarta Authentication application context ID
     * ({@code <virtual server name> <context path>}) under which a {@code ServerAuthModule} or
     * {@code AuthConfigProvider} is registered and looked up.
     *
     * <p>
     * When not set, Undertow's default ({@code localhost}) is used. Other servers use different names, e.g. GlassFish
     * uses {@code server}, which matters for registrations made with a fixed application context ID.
     */
    Optional<String> virtualServerName();
}
