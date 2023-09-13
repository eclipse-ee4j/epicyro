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

import java.util.logging.Level;
import java.util.logging.Logger;

public class LogManager {

    /**
     * PACKAGE_ROOT the prefix for the packages where logger resource bundles reside.
     */
    public static final String PACKAGE_ROOT = "com.sun.logging.";

    /**
     * RESOURCE_BUNDLE the name of the logging resource bundles.
     */
    public static final String RESOURCE_BUNDLE = "LogStrings";
    public static final String JASPIC_LOGGER = "enterprise.system.jaspic.security";
    public static final String RES_BUNDLE = PACKAGE_ROOT + JASPIC_LOGGER + "." + RESOURCE_BUNDLE;

    private String loggerName;

    public LogManager(String loggerName) {
        this.loggerName = loggerName;
    }

    protected boolean isLoggable(Level level) {
        return Logger.getLogger(loggerName).isLoggable(level);
    }

    protected void logIfLevel(Level level, Throwable t, String... msgParts) {
        Logger logger = Logger.getLogger(loggerName);

        if (logger.isLoggable(level)) {
            StringBuilder msgB = new StringBuilder();
            for (String m : msgParts) {
                msgB.append(m);
            }

            String msg = msgB.toString();
            if (!msg.isEmpty() && t != null) {
                logger.log(level, msg, t);
            } else if (!msg.isEmpty()) {
                logger.log(level, msg);
            }
        }
    }

    /**
     *
     * @param level the level to get the logger at
     * @return the logger if the level is loggable, otherwise null
     */
    protected Logger getLogger(Level level) {
        Logger logger = Logger.getLogger(loggerName);
        if (logger.isLoggable(level)) {
            return logger;
        }

        return null;
    }


}
