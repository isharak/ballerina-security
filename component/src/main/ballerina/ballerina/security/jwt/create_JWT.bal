package ballerina.security.jwt;


import ballerina.security.signature;
import ballerina.util;
@Description {value:"Represents JWT issuer configurations"}
public struct JWTIssuerConfig {
    string certificateAlias;
}

public function createJWT (Header header, Payload payload, JWTIssuerConfig config) (string, error) {
    string jwtHeader = createHeader(header);
    string jwtPayload = createPayload(payload);
    string jwtAssertion = jwtHeader + "." + jwtPayload;
    string signature = signature:sign(jwtAssertion, header.alg, config.certificateAlias);
    return jwtAssertion + "." + signature, null;

}

function createHeader (Header header) (string) {
    json headerJson = {};
    headerJson[ALG] = header.alg;
    headerJson[TYP] = "JWT";
    headerJson = addMapToJson(headerJson, header.customClaims);
    return urlEncode(util:base64Encode(headerJson.toString()));
}

function createPayload (Payload payload) (string) {
    json payloadJson = {};
    payloadJson[SUB] = payload.sub;
    payloadJson[ISS] = payload.iss;
    payloadJson[EXP] = payload.exp;
    payloadJson[IAT] = payload.iat;
    payloadJson[AUD] = convertStringArrayToJson(payload.aud);
    payloadJson = addMapToJson(payloadJson, payload.customClaims);
    return urlEncode(util:base64Encode(payloadJson.toString()));

}

function urlEncode (string data) (string) {
    string encodedString = data.replaceAll("\\+", "-");
    encodedString = encodedString.replaceAll("/", "_");
    return encodedString;
}

function addMapToJson (json inJson, map mapToConvert) (json) {
    if (mapToConvert != null) {
        foreach key in mapToConvert.keys() {
            if (typeof mapToConvert[key] == typeof string[]) {
                var inputArray, e = (string[])mapToConvert[key];
                inJson[key] = convertStringArrayToJson(inputArray);
            } else if (typeof mapToConvert[key] == typeof int[]) {
                var inputArray, e = (int[])mapToConvert[key];
                inJson[key] = convertIntArrayToJson(inputArray);
            } else if (typeof mapToConvert[key] == typeof string) {
                var inputString, _ = (string)mapToConvert[key];
                inJson[key] = inputString;
            } else if (typeof mapToConvert[key] == typeof int) {
                var inputInt, _ = (int)mapToConvert[key];
                inJson[key] = inputInt;
            } else if (typeof mapToConvert[key] == typeof boolean) {
                var inputBool, _ = (boolean)mapToConvert[key];
                inJson[key] = inputBool;
            }
        }
    }
    return inJson;
}

function convertStringArrayToJson (string[] arrayToConvert) (json) {
    json jsonPayload = [];
    int i = 0;
    while (i < lengthof arrayToConvert) {
        jsonPayload[i] = arrayToConvert[i];
        i = i + 1;
    }
    return jsonPayload;
}

function convertIntArrayToJson (int[] arrayToConvert) (json) {
    json jsonPayload = [];
    int i = 0;
    while (i < lengthof arrayToConvert) {
        jsonPayload[i] = arrayToConvert[i];
        i = i + 1;
    }
    return jsonPayload;
}