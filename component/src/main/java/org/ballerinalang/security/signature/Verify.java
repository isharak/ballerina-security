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

package org.ballerinalang.security.signature;

import org.ballerinalang.bre.Context;
import org.ballerinalang.bre.bvm.BLangVMErrors;
import org.ballerinalang.model.types.TypeKind;
import org.ballerinalang.model.values.BBoolean;
import org.ballerinalang.model.values.BValue;
import org.ballerinalang.natives.AbstractNativeFunction;
import org.ballerinalang.natives.annotations.Argument;
import org.ballerinalang.natives.annotations.BallerinaFunction;
import org.ballerinalang.natives.annotations.ReturnType;
import org.ballerinalang.security.jwt.crypto.JWSVerifier;
import org.ballerinalang.security.jwt.crypto.RSAVerifier;
import org.ballerinalang.security.util.KeyStore;

import java.security.interfaces.RSAPublicKey;

/**
 * Native function ballerinalang.security.signature:verify.
 */
@BallerinaFunction(
        packageName = "ballerina.security.signature",
        functionName = "verify",
        args = {
                @Argument(name = "data", type = TypeKind.STRING),
                @Argument(name = "signature", type = TypeKind.STRING),
                @Argument(name = "algorithm", type = TypeKind.STRING),
                @Argument(name = "keyAlias", type = TypeKind.STRING)
        },
        returnType = {@ReturnType(type = TypeKind.BOOLEAN)},
        isPublic = true
)
public class Verify extends AbstractNativeFunction {

    @Override
    public BValue[] execute(Context context) {
        String data = getStringArgument(context, 0);
        String signature = getStringArgument(context, 1);
        String algorithm = getStringArgument(context, 2);
        String keyAlias = getStringArgument(context, 3);
        Boolean validSignature = false;
        RSAPublicKey publicKey;

        try {
            if (keyAlias != null && !keyAlias.isEmpty()) {
                publicKey = (RSAPublicKey) KeyStore.getKeyStore().getPublicKey(keyAlias);
            } else {
                publicKey = (RSAPublicKey) KeyStore.getKeyStore()
                        .getDefaultPublicKey();
            }
            JWSVerifier verifier = new RSAVerifier(publicKey);
            validSignature = verifier.verify(data, signature, algorithm);

        } catch (Exception e) {
            return getBValues(new BBoolean(false), BLangVMErrors.createError(context, 0, e.getMessage()));
        }
        return getBValues(new BBoolean(validSignature));
    }
}
