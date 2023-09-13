package org.omnifaces.eleos.services;

import static java.util.Arrays.asList;
import static java.util.Collections.emptySet;
import static javax.xml.xpath.XPathConstants.NODESET;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.omnifaces.eleos.config.helper.Caller;
import org.omnifaces.eleos.config.helper.CallerPrincipal;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;


/**
 * A basic in-memory identity store.
 *
 * <p>
 * This identity store can function as the default identity store for among others
 * Servlet security in simple cases. Data is stored in a static Map, so there's only
 * ever one instance of this global data per application or VM (per class loader).
 *
 * <p>
 * This store is intentionally very limited, and mostly intended for testing.
 *
 * @author Arjan Tijms
 *
 */
public class InMemoryStore {

    private static final Logger LOGGER = Logger.getLogger(InMemoryStore.class.getName());

    public static class Credential {

        private final String callerName;
        private final String password;
        private final List<String> groups;

        public Credential(String callerName, String password, List<String> groups) {
            super();
            this.callerName = callerName;
            this.password = password;
            this.groups = groups;
        }

        /**
         * Return the caller name
         *
         * @return the caller name
         */
        public String getCallerName() {
            return callerName;
        }

        /**
         * Return the password
         *
         * @return the password
         */
        public String getPassword() {
            return password;
        }

        /**
         * Return the groups
         *
         * @return the groups
         */
        public List<String> getGroups() {
            return groups;
        }
    }

    /**
     * Stores the caller to credentials map.
     */
    private static final Map<String, Credential> CALLER_TO_CREDENTIALS = new ConcurrentHashMap<>();

    public static void initFromString(String callersAsXml) {
        if (isEmpty(callersAsXml)) {
            return;
        }

        try {
            XPath xPath = XPathFactory
                    .newInstance()
                    .newXPath();

            NodeList nodes = (NodeList) xPath
                    .evaluate(
                            "//caller",
                            DocumentBuilderFactory
                                    .newInstance()
                                    .newDocumentBuilder()
                                    .parse(new ByteArrayInputStream(callersAsXml.getBytes())),
                            NODESET);

            for (int i = 0; i < nodes.getLength(); i++) {
                NamedNodeMap callerAttributes = nodes.item(i).getAttributes();

                String caller = callerAttributes.getNamedItem("callername").getNodeValue();
                String password = callerAttributes.getNamedItem("password").getNodeValue();
                String groups = callerAttributes.getNamedItem("groups").getNodeValue();

                addCredential(caller, password, asList(groups.split(",")));
            }

        } catch (SAXException | IOException | ParserConfigurationException | XPathExpressionException e) {
            LOGGER.log(Level.WARNING, "Unable to get caller credentials", e);
        }

    }


    /**
     * Returns the caller to credentials map.
     *
     * @return the caller to credentials map.
     */
    public static Map<String, Credential> getCALLER_TO_CREDENTIALS() {
        return CALLER_TO_CREDENTIALS;
    }

    /**
     * Add the credential.
     *
     * @param callerName the caller name.
     * @param password the password.
     * @param groups the groups.
     */
    public static void addCredential(String callerName, String password, List<String> groups) {
        addCredential(new Credential(callerName, password, groups));
    }

    /**
     * Add the credential.
     *
     * @param credential the credential.
     */
    public static void addCredential(Credential credential) {
        CALLER_TO_CREDENTIALS.put(credential.getCallerName(), credential);
    }

    /**
     * Validate the username password credential.
     *
     * @param callerName the caller name to validate
     * @param password the password to validate the caller name against
     * @return the credential validation result.
     */
    public static Caller validate(String callerName, String password) {
        if (callerName == null) {
            return null;
        }

        Credential credential = CALLER_TO_CREDENTIALS.get(callerName);

        if (credential != null && password != null && password.equals(credential.getPassword())) {
            return new Caller(
                new CallerPrincipal(credential.getCallerName()),
                new HashSet<>(credential.getGroups())
            );
        }

        return null;
    }

    public static Set<String> getCallerGroups(String callerName) {
        Credential credentials = CALLER_TO_CREDENTIALS.get(callerName);

        return credentials != null ? new HashSet<>(credentials.getGroups()) : emptySet();
    }

    private static boolean isEmpty(String string) {
        return string == null || string.isEmpty();
    }

}
