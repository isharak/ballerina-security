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

/**
 * Provides the supported algorithms
 */
public class RSASSAProvider {

    /**
     * Gets the matching Java Cryptography Architecture (JCA) algorithm
     * name for the specified RSA-based JSON Web Algorithm (JWA).
     *
     * @param alg The JSON Web Algorithm (JWA). Must be supported and not
     *            {@code null}.
     * @return The matching JCA algorithm name.
     * @throws JWSException If the algorithm is not supported.
     */
    protected static String getJCAAlgorithmName(final String alg)
            throws JWSException {

        if (alg.equals(JWSAlgorithm.RS256)) {
            return "SHA256withRSA";
        } else if (alg.equals(JWSAlgorithm.RS384)) {
            return "SHA384withRSA";
        } else if (alg.equals(JWSAlgorithm.RS512)) {
            return "SHA512withRSA";
        } else {
            throw new JWSException("Unsupported JWS algorithm" + alg);
        }
    }

}
