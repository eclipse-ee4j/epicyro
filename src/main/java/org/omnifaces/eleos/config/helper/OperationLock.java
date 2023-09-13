/*
 * Copyright (c) 2019 OmniFaces. All rights reserved.
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

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.function.Supplier;

public class OperationLock {

    public final Lock readLock;
    public final Lock writeLock;

    public OperationLock(ReadWriteLock readWriteLock) {
        readLock = readWriteLock.readLock();
        writeLock = readWriteLock.writeLock();
    }

    public void doLocked(Supplier<Boolean> condition, Runnable runnable) {
        if (doReadLocked(condition)) {
            doWriteLocked(() -> {
                if (condition.get()) {
                    runnable.run();
                }
            });
        }
    }


    public <T> T doReadLocked(Supplier<T> supplier) {
        readLock.lock();
        try {
            return supplier.get();
        } finally {
            readLock.unlock();
        }
    }

    public <T> T doWriteLocked(Supplier<T> supplier) {
        writeLock.lock();
        try {
            return supplier.get();
        } finally {
            writeLock.unlock();
        }
    }

    public void doWriteLocked(Runnable runnable) {
        writeLock.lock();
        try {
            runnable.run();
        } finally {
            writeLock.unlock();
        }
    }

}
