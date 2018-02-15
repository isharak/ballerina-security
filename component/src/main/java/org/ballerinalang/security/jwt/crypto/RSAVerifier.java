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

package org.ballerinalang.security.jwt.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

/**
 *
 * @since 0.96.0
 */
public class RSAVerifier implements JWSVerifier {

    /**
     * The public RSA key.
     */
    private final RSAPublicKey publicKey;

    public RSAVerifier(final RSAPublicKey publicKey) {

        this.publicKey = publicKey;

    }

    @Override
    public boolean verify(String signingInput, String signature, String algorithm) throws JWSException {

        final Signature signatureVerifier;
        try {
            signatureVerifier = Signature.getInstance(
                    RSASSAProvider.getJCAAlgorithmName(algorithm));

            signatureVerifier.initVerify(publicKey);
            signatureVerifier.update(signingInput.getBytes());
            return signatureVerifier.verify(Base64.getUrlDecoder().decode(signature));
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new JWSException(e.getMessage(), e);
        }
    }
}
