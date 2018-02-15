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

package org.ballerinalang.auth;

import org.ballerinalang.bre.Context;
import org.ballerinalang.bre.bvm.BLangVMStructs;
import org.ballerinalang.model.types.TypeKind;
import org.ballerinalang.model.values.BStruct;
import org.ballerinalang.model.values.BValue;
import org.ballerinalang.natives.AbstractNativeFunction;
import org.ballerinalang.natives.annotations.Argument;
import org.ballerinalang.natives.annotations.BallerinaFunction;
import org.ballerinalang.natives.annotations.ReturnType;
import org.ballerinalang.util.codegen.PackageInfo;
import org.ballerinalang.util.codegen.StructInfo;

/**
 * Sample native function.
 * Refer org.ballerinalang.nativeimpl.user.GetLocale
 */
@BallerinaFunction(
        packageName = "ballerina.auth",
        functionName = "authentiacteWithContext",
        args = {@Argument(name = "val", type = TypeKind.STRING)},
        returnType = {@ReturnType(type = TypeKind.STRUCT, structType = "User", structPackage = "ballerina.auth")},
        isPublic = true
)
public class AuthentiacteWithContext extends AbstractNativeFunction {

    public BValue[] execute(Context context) {

        return new BValue[]{createUserContext(context)};
    }

    private BStruct createUserContext(Context context) {
        String name = getStringArgument(context, 0);
        PackageInfo utilsPackageInfo = context.getProgramFile().getPackageInfo("ballerina.auth");
        StructInfo localeStructInfo = utilsPackageInfo.getStructInfo("User");
        return BLangVMStructs.createBStruct(localeStructInfo,
                "2819c223-7f76-453a-919d-413861904646",
                name,
                true);
    }
}
