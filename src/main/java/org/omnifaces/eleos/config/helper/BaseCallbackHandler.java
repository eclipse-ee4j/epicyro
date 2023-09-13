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

/*
 * BaseContainerCallbackHandler.java
 *
 * Created on April 21, 2004, 11:56 AM
 */

package org.omnifaces.eleos.config.helper;

import static java.util.Collections.list;
import static java.util.logging.Level.FINE;
import static java.util.logging.Level.WARNING;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Logger;

import javax.crypto.SecretKey;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;

import org.omnifaces.eleos.services.InMemoryStore;

import jakarta.security.auth.message.callback.CallerPrincipalCallback;
import jakarta.security.auth.message.callback.CertStoreCallback;
import jakarta.security.auth.message.callback.GroupPrincipalCallback;
import jakarta.security.auth.message.callback.PasswordValidationCallback;
import jakarta.security.auth.message.callback.PrivateKeyCallback;
import jakarta.security.auth.message.callback.SecretKeyCallback;
import jakarta.security.auth.message.callback.TrustStoreCallback;

public abstract class BaseCallbackHandler implements CallbackHandler {

    public static final Logger LOG = Logger.getLogger(ModuleConfigurationManager.class.getName());

    private static final String DEFAULT_DIGEST_ALGORITHM = "SHA-1";

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        if (callbacks == null) {
            return;
        }

        for (Callback callback : callbacks) {
            if (!isSupportedCallback(callback)) {
                throw new UnsupportedCallbackException(callback, callback.getClass().getName());
            }
        }

        handleSupportedCallbacks(callbacks);
    }

    protected void processCallback(Callback callback) throws UnsupportedCallbackException {
        if (callback instanceof CallerPrincipalCallback) {
            processCallerPrincipal((CallerPrincipalCallback) callback);
        } else if (callback instanceof GroupPrincipalCallback) {
            processGroupPrincipal((GroupPrincipalCallback) callback);
        } else if (callback instanceof PasswordValidationCallback) {
            processPasswordValidation((PasswordValidationCallback) callback);
        } else if (callback instanceof PrivateKeyCallback) {
            processPrivateKey((PrivateKeyCallback) callback);
        } else if (callback instanceof TrustStoreCallback) {
            processTrustStore((TrustStoreCallback) callback);
        } else if (callback instanceof CertStoreCallback) {
            processCertStore((CertStoreCallback) callback);
        } else if (callback instanceof SecretKeyCallback) {
            processSecretKey((SecretKeyCallback) callback);
        } else {
            throw new UnsupportedCallbackException(callback);
        }
    }

    private void processCallerPrincipal(CallerPrincipalCallback callerPrincipalCallback) {
        Subject subject = callerPrincipalCallback.getSubject();
        Principal principal = callerPrincipalCallback.getPrincipal();

        if (principal == null) {
            principal = new CallerPrincipal(callerPrincipalCallback.getName());
        }

        Caller caller = Caller.fromSubject(subject);
        if (caller == null) {
            Caller.toSubject(subject, new Caller(principal));
        } else {
            caller.setCallerPrincipal(principal);
        }
    }

    private void processGroupPrincipal(GroupPrincipalCallback groupCallback) {
        Subject subject = groupCallback.getSubject();
        String[] groups = groupCallback.getGroups();

        Caller caller = Caller.fromSubject(subject);

        if (groups != null && groups.length > 0) {
            if (caller == null) {
                Caller.toSubject(subject, new Caller(groups));
            } else {
                caller.addGroups(groups);
            }
        } else if (groups == null && caller != null) {
            caller.getGroups().clear();
        }
    }

    protected void processPasswordValidation(PasswordValidationCallback pwdCallback) {
        // Default to a very basic in memory identity store.
        // Clients may want to override this for more advanced features.
        Caller caller = InMemoryStore.validate(pwdCallback.getUsername(), getPassword(pwdCallback));
        if (caller != null) {
            processCallerPrincipal(new CallerPrincipalCallback(pwdCallback.getSubject(), caller.getCallerPrincipal()));
            if (!caller.getGroups().isEmpty()) {
                processGroupPrincipal(new GroupPrincipalCallback(pwdCallback.getSubject(), caller.getGroupsAsArray()));
            }
            pwdCallback.setResult(true);
        }
    }

    protected void processTrustStore(TrustStoreCallback trustStoreCallback) {
        trustStoreCallback.setTrustStore(getTrustStore());
    }

    protected void processPrivateKey(PrivateKeyCallback privateKeyCallback) {
        KeyStore[] keyStores = getKeyStores();

        // Make sure we have a keystore
        if (isEmpty(keyStores)) {
            // Cannot get any information
            privateKeyCallback.setKey(null, null);
            return;
        }

        // Get the request type
        PrivateKeyCallback.Request request = privateKeyCallback.getRequest();
        PrivateKey privateKey = null;
        Certificate[] certificateChain = null;

        if (request == null) {
            // No request type - set default key
            PrivateKeyEntry privateKeyEntry = getDefaultPrivateKeyEntry(keyStores);
            if (privateKeyEntry != null) {
                privateKey = privateKeyEntry.getPrivateKey();
                certificateChain = privateKeyEntry.getCertificateChain();
            }

            privateKeyCallback.setKey(privateKey, certificateChain);
            return;
        }

        // Find key based on request type
        try {
            if (request instanceof PrivateKeyCallback.AliasRequest) {
                PrivateKeyCallback.AliasRequest aliasRequest = (PrivateKeyCallback.AliasRequest) request;

                String alias = aliasRequest.getAlias();
                PrivateKeyEntry privateKeyEntry;

                if (alias == null) {
                    // Use default key
                    privateKeyEntry = getDefaultPrivateKeyEntry(keyStores);
                } else {
                    privateKeyEntry = getPrivateKeyEntryFromTokenAlias(alias);
                }

                if (privateKeyEntry != null) {
                    privateKey = privateKeyEntry.getPrivateKey();
                    certificateChain = privateKeyEntry.getCertificateChain();
                }
            } else if (request instanceof PrivateKeyCallback.IssuerSerialNumRequest) {
                PrivateKeyCallback.IssuerSerialNumRequest issuerSerialNumRequest = (PrivateKeyCallback.IssuerSerialNumRequest) request;

                X500Principal issuer = issuerSerialNumRequest.getIssuer();
                BigInteger serialNum = issuerSerialNumRequest.getSerialNum();

                if (issuer != null && serialNum != null) {
                    boolean found = false;

                    for (int i = 0; i < keyStores.length && !found; i++) {
                        Enumeration<String> aliases = keyStores[i].aliases();
                        while (aliases.hasMoreElements() && !found) {
                            String nextAlias = aliases.nextElement();
                            PrivateKey key = getPrivateKeyForAlias(nextAlias, i);
                            if (key != null) {
                                Certificate[] certificates = keyStores[i].getCertificateChain(nextAlias);
                                // Check issuer/serial
                                X509Certificate eeCert = (X509Certificate) certificates[0];
                                if (eeCert.getIssuerX500Principal().equals(issuer) && eeCert.getSerialNumber().equals(serialNum)) {
                                    privateKey = key;
                                    certificateChain = certificates;
                                    found = true;
                                }
                            }
                        }
                    }
                }
            } else if (request instanceof PrivateKeyCallback.SubjectKeyIDRequest) {
                PrivateKeyCallback.SubjectKeyIDRequest subjectKeyIDRequest = (PrivateKeyCallback.SubjectKeyIDRequest) request;
                byte[] subjectKeyID = subjectKeyIDRequest.getSubjectKeyID();

                if (subjectKeyID != null) {
                    boolean found = false;

                    X509CertSelector selector = new X509CertSelector();
                    selector.setSubjectKeyIdentifier(toDerOctetString(subjectKeyID));

                    for (int i = 0; i < keyStores.length && !found; i++) {
                        Enumeration<String> aliases = keyStores[i].aliases();
                        while (aliases.hasMoreElements() && !found) {
                            String nextAlias = aliases.nextElement();
                            PrivateKey key = getPrivateKeyForAlias(nextAlias, i);

                            if (key != null) {
                                Certificate[] certificates = keyStores[i].getCertificateChain(nextAlias);

                                if (selector.match(certificates[0])) {
                                    privateKey = key;
                                    certificateChain = certificates;
                                    found = true;
                                }
                            }
                        }
                    }
                }
            } else if (request instanceof PrivateKeyCallback.DigestRequest) {
                PrivateKeyCallback.DigestRequest digestRequest = (PrivateKeyCallback.DigestRequest) request;
                byte[] digest = digestRequest.getDigest();
                String algorithm = digestRequest.getAlgorithm();

                PrivateKeyEntry privateKeyEntry = null;
                if (digest == null) {
                    // Get default key
                    privateKeyEntry = getDefaultPrivateKeyEntry(keyStores);
                } else {
                    if (algorithm == null) {
                        algorithm = DEFAULT_DIGEST_ALGORITHM;
                    }
                    MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
                    privateKeyEntry = getPrivateKeyEntry(keyStores, messageDigest, digest);
                }

                if (privateKeyEntry != null) {
                    privateKey = privateKeyEntry.getPrivateKey();
                    certificateChain = privateKeyEntry.getCertificateChain();
                }
            } else {
                LOG.log(FINE, () -> "invalid request type: " + request.getClass().getName());
            }
        } catch (Exception e) {
            // UnrecoverableKeyException
            // NoSuchAlgorithmException
            // KeyStoreException
            LOG.log(FINE, "Jakarta Authentication: In PrivateKeyCallback Processor: Error reading key !", e);
        } finally {
            privateKeyCallback.setKey(privateKey, certificateChain);
        }
    }

    protected PrivateKeyEntry getDefaultPrivateKeyEntry(KeyStore[] keyStores) {
        PrivateKey privateKey = null;
        Certificate[] certificates = null;
        try {
            for (int i = 0; i < keyStores.length && privateKey == null; i++) {
                Enumeration<String> aliases = keyStores[i].aliases();

                // Loop through aliases and try to get the key/chain
                while (aliases.hasMoreElements() && privateKey == null) {
                    String nextAlias = aliases.nextElement();
                    privateKey = null;
                    certificates = null;
                    PrivateKey key = getPrivateKeyForAlias(nextAlias, i);
                    if (key != null) {
                        privateKey = key;
                        certificates = keyStores[i].getCertificateChain(nextAlias);
                    }
                }
            }
        } catch (Exception e) {
            LOG.log(FINE, "Exception in getDefaultPrivateKeyEntry", e);
        }

        return new PrivateKeyEntry(privateKey, certificates);
    }

    protected PrivateKey getPrivateKeyForAlias(String alias, int keystoreIndex) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return null;
    }

    protected PrivateKeyEntry getPrivateKeyEntryFromTokenAlias(String certNickname) throws Exception {
        return null;
    }

    protected void processCertStore(CertStoreCallback certStoreCallback) {
        LOG.log(FINE, "Jakarta Authentication: In CertStoreCallback Processor");

        KeyStore certStore = getTrustStore();
        if (certStore == null) { // should never happen (but of course, it practice it will)
            certStoreCallback.setCertStore(null);
        }

        List<Certificate> certificates = new ArrayList<>();
        try {
            if (certStore != null) {
                for (String alias : list(certStore.aliases())) {
                    if (certStore.isCertificateEntry(alias)) {
                        try {
                            certificates.add(certStore.getCertificate(alias));
                        } catch (KeyStoreException kse) {
                            // ignore and move to next
                            LOG.log(FINE, () -> "Jakarta Authentication: Cannot retrieve certificate for alias " + alias);
                        }
                    }
                }
            }

            certStoreCallback.setCertStore(
                CertStore.getInstance("Collection", new CollectionCertStoreParameters(certificates)));
        } catch (KeyStoreException kse) {
            LOG.log(FINE, "Jakarta Authentication:  Cannot determine truststore aliases", kse);
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException nsape) {
            LOG.log(FINE, "Jakarta Authentication:  Cannot instantiate CertStore", nsape);
        }
    }

    protected void processSecretKey(SecretKeyCallback secretKeyCallback) {
        LOG.log(FINE, "Jakarta Authentication: In SecretKeyCallback Processor");

        String alias = ((SecretKeyCallback.AliasRequest) secretKeyCallback.getRequest()).getAlias();
        if (alias != null) {
            try {
                secretKeyCallback.setKey(getPasswordSecretKeyForAlias(alias));
            } catch (Exception e) {
                LOG.log(FINE, e, () -> "Jakarta Authentication: In SecretKeyCallback Processor: " + " Error reading key ! for alias " + alias);
                secretKeyCallback.setKey(null);
            }
        } else {
            // Don't bother about checking for principal. We don't support that feature - typically
            // used in an environment with kerberos
            secretKeyCallback.setKey(null);
            LOG.log(WARNING, "No support to read Principals in SecretKeyCallback.");
        }
    }

    protected KeyStore getTrustStore() {
        return null;
    }

    protected KeyStore[] getKeyStores() {
        return null;
    }

    protected SecretKey getPasswordSecretKeyForAlias(String alias) throws GeneralSecurityException {
        return null;
    }

    protected abstract boolean isSupportedCallback(Callback callback);

    protected abstract void handleSupportedCallbacks(Callback[] callbacks) throws IOException, UnsupportedCallbackException;

    private String getPassword(PasswordValidationCallback pwdCallback) {
        char[] password = pwdCallback.getPassword();
        if (password == null) {
            return null;
        }

        return new String(password);
    }

    private byte[] toDerOctetString(byte[] value) throws IOException {
        ByteArrayOutputStream subjectOutputStream = new ByteArrayOutputStream();

        subjectOutputStream.write(0x04); // DER Octet String tag
        subjectOutputStream.write(length2Bytes(value.length));
        subjectOutputStream.write(value);

        return subjectOutputStream.toByteArray();
    }

    /**
     * Splits out an integer into a variable number of bytes with the first byte containing either the number of bytes, or
     * the integer itself if small enough.
     *
     * @param length the integer to convert
     * @return the integer in DER byte array form
     */
    private byte[] length2Bytes(int length) {
        // The first byte with the MSB bit a 0 encodes the direct length
        // E.g. 0b00000001 for length = 1
        if (length <= 127) {
            return new byte[] { (byte) length };
        }

        // Count how many bytes are in the "length" integer
        int byteCount = 1;
        int lengthValue = length;

        while ((lengthValue >>>= 8) != 0) {
            byteCount++;
        }

        byte[] lengthBytes = new byte[byteCount + 1];

        // The first byte with the MSB bit a 1 encodes the number of bytes used for the length
        // E.g. 0b10000001 for 1 additional byte (for values up to 255)
        lengthBytes[0] = (byte) (byteCount | 0b10000000);

        // Shift the integer in increments of 8 bits, and truncate the lowest 8 ones in every iteration.
        // For numbers up to 255 shift 0 times, e.g. for length 255 take the binary version 0b11111111 directly.
        // For numbers up to 65535 shift 1 time, e.g. for length 256
        // first byte = 0b100000000 >> 8 = 0b000000001 -> 0b00000001
        // second byte = 0b100000000 >> 0 = 0b000000000 -> 0b00000000
        int pos = 1;
        for (int i = (byteCount - 1) * 8; i >= 0; i -= 8) {
            lengthBytes[pos] = (byte) (length >> i);
            pos++;
        }

        return lengthBytes;
    }

    private PrivateKeyEntry getPrivateKeyEntry(KeyStore[] keyStores, MessageDigest messageDigest, byte[] digest) {
        PrivateKey privateKey = null;
        Certificate[] certificates = null;
        try {
            for (int i = 0; i < keyStores.length && privateKey == null; i++) {
                Enumeration<String> aliases = keyStores[i].aliases();

                // Loop thru aliases and try to get the key/chain
                while (aliases.hasMoreElements() && privateKey == null) {
                    String nextAlias = aliases.nextElement();
                    privateKey = null;
                    certificates = null;
                    PrivateKey key = getPrivateKeyForAlias(nextAlias, i);
                    if (key != null) {
                        certificates = keyStores[i].getCertificateChain(nextAlias);
                        messageDigest.reset();
                        byte[] cDigest = messageDigest.digest(certificates[0].getEncoded());
                        if (Arrays.equals(digest, cDigest)) {
                            privateKey = key;
                        }
                    }
                }
            }
        } catch (Exception e) {
            // UnrecoverableKeyException
            // NoSuchAlgorithmException
            // KeyStoreException
            LOG.log(FINE, "Exception in getPrivateKeyEntry for Digest", e);
        }

        return new PrivateKeyEntry(privateKey, certificates);
    }

    private static boolean isEmpty(Object[] array) {
        return array == null || array.length == 0;
    }

}
