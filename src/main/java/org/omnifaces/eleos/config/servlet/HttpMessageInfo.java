/*
 * Copyright (c) 1997, 2018 Oracle and/or its affiliates, and OmniFaces. 
 * All rights reserved.
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

package org.omnifaces.eleos.config.servlet;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.message.MessageInfo;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HttpMessageInfo implements MessageInfo {

    private HttpServletRequest servletRequest;
    private HttpServletResponse servletResponse;
    private Map<String, Object> map = new HashMap<>();

    public HttpMessageInfo(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        this.servletRequest = servletRequest;
        this.servletResponse = servletResponse;
    }

    @Override
    public HttpServletRequest getRequestMessage() {
        return servletRequest;
    }

    @Override
    public HttpServletResponse getResponseMessage() {
        return servletResponse;
    }

    @Override
    public void setRequestMessage(Object servletRequest) {
        this.servletRequest = (HttpServletRequest) servletRequest;
    }

    @Override
    public void setResponseMessage(Object servletResponse) {
        this.servletResponse = (HttpServletResponse) servletResponse;
    }

    @Override
    public Map<String, Object> getMap() {
        return map;
    }
}