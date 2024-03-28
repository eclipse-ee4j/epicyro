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

package org.glassfish.epicyro.config.factory.file;

import static java.util.logging.Level.FINER;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.WARNING;
import static org.glassfish.epicyro.config.helper.LogManager.JASPIC_LOGGER;
import static org.glassfish.epicyro.config.helper.LogManager.RES_BUNDLE;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.logging.Logger;

import org.glassfish.epicyro.config.factory.RegistrationContextImpl;

import jakarta.security.auth.message.config.AuthConfigFactory.RegistrationContext;

/**
 * Used by ServerConfigProvider to parse the configuration file. If a file does not exist originally, the default
 * providers are not used. A file is only created if needed, which happens if providers are registered or unregistered
 * through the store() or delete() methods.
 *
 * @author Bobby Bissett
 */
public final class RegStoreFileParser {

    private static final Logger logger = Logger.getLogger(JASPIC_LOGGER, RES_BUNDLE);

    private static final String SEP = ":";
    private static final String CON_ENTRY = "con-entry";
    private static final String REG_ENTRY = "reg-entry";
    private static final String REG_CTX = "reg-ctx";
    private static final String LAYER = "layer";
    private static final String APP_CTX = "app-ctx";
    private static final String DESCRIPTION = "description";
    private static final String[] INDENT = { "", "  ", "    " };

    private File configurationFile;
    private List<AuthConfigProviderEntry> authConfigProviderEntries;

    public RegStoreFileParser(List<AuthConfigProviderEntry> authConfigProviderEntries) {
        this.authConfigProviderEntries = new ArrayList<>(authConfigProviderEntries);
    }

    /**
     * Loads the configuration file from the given filename. If a file is not found, then the default authConfigProviderEntries are used.
     * Otherwise the file is parsed to load the authConfigProviderEntries.
     *
     */
    public RegStoreFileParser(String pathParent, String pathChild, List<AuthConfigProviderEntry> defaultEntries) {
        configurationFile = new File(pathParent, pathChild);

        try {
            loadEntries(defaultEntries);
        } catch (IOException | IllegalArgumentException e) {
            logger.log(WARNING, "Could not read auth configuration file. Will use default providers.", e);
        }
    }

    /**
     * Returns the in-memory list of authConfigProviderEntries. MUST Hold exclusive lock on calling factory while processing authConfigProviderEntries
     */
    public List<AuthConfigProviderEntry> getPersistedEntries() {
        return authConfigProviderEntries;
    }

    /**
     * Adds the provider to the entry list if it is not already present, creates the configuration file if necessary, and
     * writes the authConfigProviderEntries to the file.
     */
    public void store(String className, RegistrationContext registrationContext, Map<String, String> properties) {
        synchronized (configurationFile) {
            if (checkAndAddToList(className, registrationContext, properties)) {
                try {
                    writeEntries();
                } catch (IOException ioe) {
                    logger.log(WARNING,
                        "Could not persist updated provider list. Will use default providers when reloaded.", ioe);
                }
            }
        }
    }

    /**
     * Removes the provider from the entry list if it is already present, creates the configuration file if necessary, and
     * writes the authConfigProviderEntries to the file.
     */
    public void delete(RegistrationContext registrationContext) {
        synchronized (configurationFile) {
            if (checkAndRemoveFromList(registrationContext)) {
                try {
                    writeEntries();
                } catch (IOException ioe) {
                    logger.log(WARNING,
                        "Could not persist updated provider list. Will use default providers when reloaded.", ioe);
                }
            }
        }
    }

    /**
     * If this entry does not exist, this method stores it in the authConfigProviderEntries list and returns true to indicate that the
     * configuration file should be written.
     */
    private boolean checkAndAddToList(String className, RegistrationContext registrationContext, Map<String, String> properties) {

        // Convention is to use null for empty properties
        if (properties != null && properties.isEmpty()) {
            properties = null;
        }

        AuthConfigProviderEntry newEntry = new AuthConfigProviderEntry(className, properties, registrationContext);
        AuthConfigProviderEntry entry = getMatchingRegistrationEntry(newEntry);

        // There is no matching entry, so add to list
        if (entry == null) {
            authConfigProviderEntries.add(newEntry);
            return true;
        }

        // Otherwise, check reg contexts to see if there is a match
        if (entry.getRegistrationContexts().contains(registrationContext)) {
            return false;
        }

        // No matching context in existing entry, so add to existing entry
        entry.getRegistrationContexts().add(new RegistrationContextImpl(registrationContext));

        return true;
    }

    /**
     * If this registration context does not exist, this method returns false. Otherwise it removes the entry and returns
     * true to indicate that the configuration file should be written.
     *
     * This only makes sense for registry authConfigProviderEntries.
     */
    private boolean checkAndRemoveFromList(RegistrationContext target) {
        boolean retValue = false;
        try {
            ListIterator<AuthConfigProviderEntry> lit = authConfigProviderEntries.listIterator();
            while (lit.hasNext()) {

                AuthConfigProviderEntry info = lit.next();
                if (info.isConstructorEntry()) {
                    continue;
                }

                Iterator<RegistrationContext> iter = info.getRegistrationContexts().iterator();
                while (iter.hasNext()) {
                    RegistrationContext ctx = iter.next();
                    if (ctx.equals(target)) {
                        iter.remove();
                        if (info.getRegistrationContexts().isEmpty()) {
                            lit.remove();
                        }
                        retValue = true;
                    }
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return retValue;
    }

    /**
     * Used to find a matching registration entry in the 'authConfigProviderEntries' list without including registration contexts. If there is
     * not a matching entry, return null.
     */
    private AuthConfigProviderEntry getMatchingRegistrationEntry(AuthConfigProviderEntry target) {
        for (AuthConfigProviderEntry info : authConfigProviderEntries) {
            if (!info.isConstructorEntry() && info.matchConstructors(target)) {
                return info;
            }
        }

        return null;
    }

    /**
     * This method overwrites the existing file with the current authConfigProviderEntries.
     */
    private void writeEntries() throws IOException {
        if (configurationFile.exists() && !configurationFile.canWrite() && logger.isLoggable(WARNING)) {
            logger.log(WARNING, "Cannot write to file {0}. Updated provider list will not be persisted.", configurationFile);
        }

        clearExistingFile();

        PrintWriter out = new PrintWriter(configurationFile);
        int indent = 0;
        for (AuthConfigProviderEntry info : authConfigProviderEntries) {
            if (info.isConstructorEntry()) {
                writeConEntry(info, out, indent);
            } else {
                writeRegEntry(info, out, indent);
            }
        }
        out.close();
    }

    /**
     * Writes constructor entry output of the form:
     *
     * <pre>
     *  con-entry { className key:value key:value }
     * </pre>
     *
     * The first appearance of a colon ":" separates the key and value of the property (so a value may contain a colon as
     * part of the string). For instance: "mydir:c:foo" would have key "mydir" and value "c:foo".
     */
    private void writeConEntry(AuthConfigProviderEntry info, PrintWriter out, int i) {
        out.println(INDENT[i++] + CON_ENTRY + " {");
        out.println(INDENT[i] + info.getClassName());

        Map<String, String> properties = info.getProperties();
        if (properties != null) {
            for (Map.Entry<String, String> val : properties.entrySet()) {
                out.println(INDENT[i] + val.getKey() + SEP + val.getValue());
            }
        }

        out.println(INDENT[--i] + "}");
    }

    /*
     * Write registration entry output of the form: <pre> reg-entry { con-entry { see writeConEntry() for detail } reg-ctx {
     * layer:HttpServlet app-ctx:security-jaspic-https description:My provider } } </pre>
     */
    private void writeRegEntry(AuthConfigProviderEntry info, PrintWriter out, int i) {
        out.println(INDENT[i++] + REG_ENTRY + " {");
        if (info.getClassName() != null) {
            writeConEntry(info, out, i);
        }

        for (RegistrationContext registrationContext : info.getRegistrationContexts()) {
            out.println(INDENT[i++] + REG_CTX + " {");
            if (registrationContext.getMessageLayer() != null) {
                out.println(INDENT[i] + LAYER + SEP + registrationContext.getMessageLayer());
            }

            if (registrationContext.getAppContext() != null) {
                out.println(INDENT[i] + APP_CTX + SEP + registrationContext.getAppContext());
            }

            if (registrationContext.getDescription() != null) {
                out.println(INDENT[i] + DESCRIPTION + SEP + registrationContext.getDescription());
            }

            out.println(INDENT[--i] + "}");
        }

        out.println(INDENT[--i] + "}");
    }

    private void clearExistingFile() throws IOException {
        boolean newCreation = !configurationFile.exists();

        if (!newCreation) {
            if (!configurationFile.delete()) {
                throw new IOException();
            }
        }

        if (newCreation) {
            logger.log(INFO, "Creating JMAC Configuration file {0}.", configurationFile);
        }

        if (!configurationFile.createNewFile()) {
            throw new IOException();
        }
    }

    /**
     * Called from the constructor. This is the only time the file is read, though it is written when new authConfigProviderEntries are stored
     * or deleted.
     */
    private void loadEntries(List<AuthConfigProviderEntry> defaultAuthConfigProviderEntries) throws IOException {
        synchronized (configurationFile) {
            authConfigProviderEntries = new ArrayList<>();
            if (configurationFile.exists()) {
                try (BufferedReader reader = new BufferedReader(new FileReader(configurationFile))) {
                    String line = reader.readLine();
                    while (line != null) {
                        String trimLine = line.trim(); // can't trim readLine() result
                        if (trimLine.startsWith(CON_ENTRY)) {
                            authConfigProviderEntries.add(readConEntry(reader));
                        } else if (trimLine.startsWith(REG_ENTRY)) {
                            authConfigProviderEntries.add(readRegEntry(reader));
                        }
                        line = reader.readLine();
                    }
                }
            } else {
                logger.log(FINER, "Configuration file {0} does not exist. Will use default providers.",
                    configurationFile);

                if (defaultAuthConfigProviderEntries != null) {
                    for (AuthConfigProviderEntry entry : defaultAuthConfigProviderEntries) {
                        authConfigProviderEntries.add(new AuthConfigProviderEntry(entry));
                    }
                }
            }
        }
    }

    private AuthConfigProviderEntry readConEntry(BufferedReader reader) throws IOException {
        // AuthModuleBaseConfig must contain class name as next line
        String className = reader.readLine();
        if (className != null) {
            className = className.trim();
        }

        return new AuthConfigProviderEntry(className, readProperties(reader));
    }

    /**
     * Properties must be of the form "key:value." While the key String cannot contain a ":" character, the value can. The
     * line will be broken into key and value based on the first appearance of the ":" character.
     */
    private Map<String, String> readProperties(BufferedReader reader) throws IOException {
        String line = reader.readLine();
        if (line != null) {
            line = line.trim();
        }

        if ("}".equals(line)) {
            return null;
        }

        Map<String, String> properties = new HashMap<>();
        while (!"}".equals(line)) {
            properties.put(line.substring(0, line.indexOf(SEP)), line.substring(line.indexOf(SEP) + 1, line.length()));
            line = reader.readLine();
            if (line != null) {
                line = line.trim();
            }
        }

        return properties;
    }

    private AuthConfigProviderEntry readRegEntry(BufferedReader reader) throws IOException {
        String className = null;
        Map<String, String> properties = null;
        List<RegistrationContext> ctxs = new ArrayList<>();
        String line = reader.readLine();
        if (line != null) {
            line = line.trim();
        }
        while (!"}".equals(line)) {
            if (line.startsWith(CON_ENTRY)) {
                AuthConfigProviderEntry conEntry = readConEntry(reader);
                className = conEntry.getClassName();
                properties = conEntry.getProperties();
            } else if (line.startsWith(REG_CTX)) {
                ctxs.add(readRegContext(reader));
            }
            line = reader.readLine();
            if (line != null) {
                line = line.trim();
            }

        }
        return new AuthConfigProviderEntry(className, properties, ctxs);
    }

    private RegistrationContext readRegContext(BufferedReader reader) throws IOException {
        String layer = null;
        String appCtx = null;
        String description = null;
        String line = reader.readLine();
        if (line != null) {
            line = line.trim();
        }

        while (!"}".equals(line)) {
            String value = line.substring(line.indexOf(SEP) + 1, line.length());
            if (line.startsWith(LAYER)) {
                layer = value;
            } else if (line.startsWith(APP_CTX)) {
                appCtx = value;
            } else if (line.startsWith(DESCRIPTION)) {
                description = value;
            }

            line = reader.readLine();
            if (line != null) {
                line = line.trim();
            }
        }

        return new RegistrationContextImpl(layer, appCtx, description, true);
    }
}
