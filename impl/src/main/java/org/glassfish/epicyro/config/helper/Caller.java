/*
 * Copyright (c) 2024 OmniFish and/or its affiliates. All rights reserved.
 * Copyright (c) 2019, 2021 OmniFaces. All rights reserved.
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

package org.glassfish.epicyro.config.helper;

import static java.util.Arrays.asList;

import java.io.Serializable;
import java.security.Principal;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import javax.security.auth.Subject;

public class Caller implements Principal, Serializable  {

    private static final long serialVersionUID = 1L;

    private Principal callerPrincipal;
    private Set<String> groups = new HashSet<>();

    public static Caller fromSubject(Subject subject) {
        Set<Caller> callers = subject.getPrincipals(Caller.class);
        if (callers == null || callers.isEmpty()) {
            return null;
        }

        return callers.iterator().next();
    }

    public static void toSubject(Subject subject, Caller caller) {
        subject.getPrincipals().add(caller);
    }

    public Caller() {
    }

    public Caller(Principal callerPrincipal) {
        this.callerPrincipal = callerPrincipal;
    }

    public Caller(String[] groups) {
        this.groups.addAll(asList(groups));
    }

    public Caller(Principal callerPrincipal, Set<String> groups) {
        this.callerPrincipal = callerPrincipal;
        this.groups.addAll(groups);
    }

    @Override
    public String getName() {
        if (callerPrincipal == null) {
            return null;
        }

        return callerPrincipal.getName();
    }

    public Principal getCallerPrincipal() {
        return callerPrincipal;
    }

    public void setCallerPrincipal(Principal callerPrincipal) {
        this.callerPrincipal = callerPrincipal;
    }

    public Set<String> getGroups() {
        return groups;
    }

    public String[] getGroupsAsArray() {
        return groups.toArray(new String[0]);
    }

    public void addGroups(String[] groups) {
        this.groups.addAll(asList(groups));
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Caller)) {
            return false;
        }

        Caller another = (Caller) o;
        return Objects.equals(getName(), another.getName());
    }


    @Override
    public int hashCode() {
        return callerPrincipal == null || callerPrincipal.getName() == null? 0 :
               31 * callerPrincipal.getName().hashCode();
    }

}
