/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.ballerinalang.security.util;

import org.ballerinalang.config.ConfigRegistry;
import org.ballerinalang.util.exceptions.BallerinaException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

/**
 * KeyStore process the configured keystore and provide an API.
 *
 * @since 0.96.0
 */
public class KeyStore {

    private static final String KEYSTORE_CONFIG = "KeyStore";
    private static final String LOCATION = "Location";
    private static final String TYPE = "Type";
    private static final String PASSWORD = "Password";
    private static final String DEFAULT_KEY_ALIAS = "KeyAlias";
    private static final String DEFAULT_KEY_PASSWORD = "KeyPassword";

    private static final KeyStore keyStoreInstance = new KeyStore();
    private java.security.KeyStore keyStore;

    private KeyStore() {

        loadKeyStore();
    }

    /**
     * Get the KeyStore.
     *
     * @return KeyStore instance
     */
    public static KeyStore getKeyStore() {

        return keyStoreInstance;
    }

    /**
     * Get the private key for a given key alias.
     *
     * @param alias
     * @param keyPassword
     * @return private key corresponding to the alias
     * @throws KeyStoreException
     */
    public PrivateKey getPrivateKey(String alias, char[] keyPassword) throws KeyStoreException {

        try {
            return (PrivateKey) keyStore.getEntry(alias, new java.security.KeyStore.PasswordProtection(keyPassword));
        } catch (Exception e) {
            throw new KeyStoreException("Failed to load private key: " + alias, e);
        }
    }

    /**
     * Get the public key for a given key alias.
     *
     * @param alias
     * @return public key corresponding to the alias.
     * @throws KeyStoreException
     */
    public PublicKey getPublicKey(String alias) throws KeyStoreException {

        Certificate certificate = getCertificate(alias);
        return (PublicKey) certificate.getPublicKey();
    }

    /**
     * Get the certificate for a given key alias.
     *
     * @param alias
     * @return certificate corresponding to the alias.
     * @throws KeyStoreException
     */
    public Certificate getCertificate(String alias) throws KeyStoreException {

        try {
            return keyStore.getCertificate(alias);
        } catch (java.security.KeyStoreException e) {
            throw new KeyStoreException("Failed to load certificate: " + alias, e);
        }
    }

    /**
     * Get the default private key of the service.
     *
     * @return default private key.
     * @throws KeyStoreException
     */
    public PrivateKey getDefaultPrivateKey() throws KeyStoreException {

        ConfigRegistry configRegistry = ConfigRegistry.getInstance();
        char[] keyStorePassword = configRegistry.getInstanceConfigValue(KEYSTORE_CONFIG, DEFAULT_KEY_PASSWORD)
                                 .toCharArray();
        String keyAlias = configRegistry.getInstanceConfigValue(KEYSTORE_CONFIG, DEFAULT_KEY_ALIAS);
        return getPrivateKey(keyAlias, keyStorePassword);
    }

    /**
     * Get the default public key of the service.
     *
     * @return default public key.
     * @throws KeyStoreException
     */
    public PublicKey getDefaultPublicKey() throws KeyStoreException {

        String keyAlias = ConfigRegistry.getInstance().getInstanceConfigValue(KEYSTORE_CONFIG, DEFAULT_KEY_ALIAS);
        return getPublicKey(keyAlias);
    }

    /**
     * Get the default certificate for a given key alias.
     *
     * @return certificate corresponding to the alias.
     * @throws KeyStoreException
     */
    public Certificate getDefaultCertificate() throws KeyStoreException {

        String keyAlias = ConfigRegistry.getInstance().getInstanceConfigValue(KEYSTORE_CONFIG, DEFAULT_KEY_ALIAS);
        return getCertificate(keyAlias);
    }

    private void loadKeyStore() {

        ConfigRegistry configRegistry = ConfigRegistry.getInstance();
        String keyStoreLocation = configRegistry.getInstanceConfigValue(KEYSTORE_CONFIG, LOCATION);
        char[] keyStorePassword = configRegistry.getInstanceConfigValue(KEYSTORE_CONFIG, PASSWORD).toCharArray();
        String keystoreType = configRegistry.getInstanceConfigValue(KEYSTORE_CONFIG, TYPE);

        try (InputStream file = new FileInputStream(new File(keyStoreLocation))) {
            keyStore = java.security.KeyStore.getInstance(keystoreType);
            keyStore.load(file, keyStorePassword);
        } catch (FileNotFoundException e) {
            throw new BallerinaException("Failed to load keystore: file not found: " + keyStoreLocation, e);
        } catch (Exception e) {
            throw new BallerinaException("Failed to load keystore: " + e.getMessage(), e);
        }
    }

}
