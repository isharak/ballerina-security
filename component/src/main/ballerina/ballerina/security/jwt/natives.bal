package ballerina.security.jwt;

import ballerina.util;
import ballerina.security.signature;

//JOSH header parameters
const string alg = "alg";
const string typ = "typ";
const string cty = "cty";
const string kid = "kid";


//Payload parameters
const string iss = "iss";
const string sub = "sub";
const string aud = "aud";
const string jti = "jti";
const string exp = "exp";
const string nbf = "nbf";
const string iat = "iat";


public struct Payload {
    string iss;
    string sub;
    string[] aud;
    string jti;
    int exp;
    int nbf;
    int iat;
    map customClaims;
}

struct Header {
    string alg;
    string typ;
    string cty;
    string kid;
    map customClaims;
}

public struct JWTValidatorConfig {
    string issuer;
    string audience;
    string certificateAlias;
}

public function verify (string jwtToken, JWTValidatorConfig config) (boolean, Payload, error) {

    string[] encodedJWTComponents = getJWTComponents(jwtToken);

    Payload payload = {};
    Header header = {};
    header, payload = parseJWT(encodedJWTComponents);

    boolean isValid;
    error e;
    isValid, e = validateJWT(encodedJWTComponents, header, payload, config);
    if (isValid) {
        return true, payload, null;
    }
    return false, null, e;
}

function getJWTComponents (string jwtToken) (string[]) {
    string[] jwtComponents = jwtToken.split("\\.");
    return jwtComponents;

}

function parseJWT (string[] encodedJWTComponents) (Header, Payload) {
    var headerJson, payloadJson = getDecodedJWTComponents(encodedJWTComponents);
    Header jwtHeader = parseHeader(headerJson);
    Payload jwtPayload = parsePayload(payloadJson);

    return jwtHeader, jwtPayload;
}

function getDecodedJWTComponents (string[] encodedJWTComponents) (json, json) {

    //TODO need to do the decoding parts of header and body (Base64URL decode is not yet implemented)
    //TODO then need to convert header data from UTF-8 to char set which is used in current version
    string jwtHeader = util:base64Decode(urlDecode(encodedJWTComponents[0]));
    string jwtPayload = util:base64Decode(urlDecode(encodedJWTComponents[1]));
    json jwtHeaderJson;
    json jwtPayloadJson;

    jwtHeaderJson, _ = <json>jwtHeader;
    jwtPayloadJson, _ = <json>jwtPayload;

    return jwtHeaderJson, jwtPayloadJson;
}

function parseHeader (json jwtHeaderJson) (Header) {
    Header jwtHeader = {};

    map customClaims = {};
    foreach k in jwtHeaderJson.getKeys() {
        string key = <string>k;
        if (key.equalsIgnoreCase(alg)) {
            jwtHeader.alg = jwtHeaderJson[key].toString();
        } else if (key.equalsIgnoreCase(typ)) {
            jwtHeader.typ = jwtHeaderJson[key].toString();
        } else if (key.equalsIgnoreCase(cty)) {
            jwtHeader.cty = jwtHeaderJson[key].toString();
        } else if (key.equalsIgnoreCase(kid)) {
            jwtHeader.kid = jwtHeaderJson[key].toString();
        } else {
            if (lengthof jwtHeaderJson[key] > 0) {
                customClaims[key] = convertToStringArray(jwtHeaderJson[key]);
            } else {
                customClaims[key] = jwtHeaderJson[key].toString();
            }
        }
    }
    jwtHeader.customClaims = customClaims;
    return jwtHeader;
}

function parsePayload (json jwtPayloadJson) (Payload) {
    Payload jwtPayload = {};

    map customClaims = {};
    foreach k in jwtPayloadJson.getKeys() {
        string key = <string>k;
        //println(typeof jwtPayloadJson[key] );
        if (key.equalsIgnoreCase(iss)) {
            jwtPayload.iss = jwtPayloadJson[key].toString();
        } else if (key.equalsIgnoreCase(sub)) {
            jwtPayload.sub = jwtPayloadJson[key].toString();
        } else if (key.equalsIgnoreCase(aud)) {
            jwtPayload.aud = convertToStringArray(jwtPayloadJson[key]);
        } else if (key.equalsIgnoreCase(jti)) {
            jwtPayload.jti = jwtPayloadJson[key].toString();
        } else if (key.equalsIgnoreCase(exp)) {
            var value = jwtPayloadJson[key].toString();
            var intVal, _ = <int>value;
            jwtPayload.exp = intVal;
        } else if (key.equalsIgnoreCase(nbf)) {
            var value = jwtPayloadJson[key].toString();
            var intVal, _ = <int>value;
            jwtPayload.nbf = intVal;
        } else if (key.equalsIgnoreCase(iat)) {
            var value = jwtPayloadJson[key].toString();
            var intVal, _ = <int>value;
            jwtPayload.iat = intVal;
        }
        else {
            if (lengthof jwtPayloadJson[key] > 0) {
                customClaims[key] = convertToStringArray(jwtPayloadJson[key]);
            } else {
                customClaims[key] = jwtPayloadJson[key].toString();
            }
        }
    }
    jwtPayload.customClaims = customClaims;
    return jwtPayload;
}

function validateJWT (string[] encodedJWTComponents, Header jwtHeader, Payload jwtPayload, JWTValidatorConfig config)
(boolean, error) {
    if (!validateMandatoryFields(jwtPayload)) {
        error err = {msg:"Mandatory fields(Issuer, Subject, Expiration time or Audience) are empty in the given JSON Web Token."};
        return false, err;
    }
    if (!validateSignature(encodedJWTComponents, jwtHeader, config)) {
        error err = {msg:"Invalide signature"};
        return false, err;
    }
    if (!validateIssuer(jwtPayload, config)) {
        error err = {msg:"No Registered IDP found for the JWT with issuer name : " + jwtPayload.iss};
        return false, err;
    }
    if (!validateAudience(jwtPayload, config)) {
        //TODO need to set expected audience or available anudience list
        error err = {msg:"Invalide audience"};
        return false, err;
    }
    if (!validateExpirationTime(jwtPayload)) {
        error err = {msg:"JWT token is expired"};
        return false, err;
    }
    if (!validateNotBeforeTime(jwtPayload)) {
        error err = {msg:"JWT token is used before Not_Before_Time"};
        return false, err;
    }
    //TODO : Need to validate jwt id (jti) and custom claims.

    return true, null;
}

function validateMandatoryFields (Payload jwtPayload) (boolean) {
    if (jwtPayload.iss == null || jwtPayload.sub == null || jwtPayload.exp == 0 || jwtPayload.aud == null) {
        return false;
    }
    return true;
}

function validateSignature (string[] encodedJWTComponents, Header jwtHeader, JWTValidatorConfig config) (boolean) {
    string assertion = encodedJWTComponents[0] + "." + encodedJWTComponents[1];
    string signPart = encodedJWTComponents[2];
    return signature:verify(assertion, signPart, jwtHeader.alg, config.certificateAlias);
}

function validateIssuer (Payload jwtPayload, JWTValidatorConfig config) (boolean) {
    return jwtPayload.iss.equalsIgnoreCase(config.issuer);
}

function validateAudience (Payload jwtPayload, JWTValidatorConfig config) (boolean) {
    foreach audience in jwtPayload.aud {
        if (audience.equalsIgnoreCase(config.audience)) {
            return true;
        }
        return false;
    }
}

function validateExpirationTime (Payload jwtPayload) (boolean) {
    return jwtPayload.exp > currentTime().time;
}

function validateNotBeforeTime (Payload jwtPayload) (boolean) {
    return currentTime().time > jwtPayload.nbf;
}

function getJWTAuthConfiguration (string key) (string) {
    //TODO validate the input and return relevant parameter
    if (key.equalsIgnoreCase("iss")) {
        return "wso2";

    } else if (key.equalsIgnoreCase("aud")) {
        return "Ballerina";
    }
    return key;
}


function urlDecode (string encodedString) (string) {
    string decodedString = encodedString.replaceAll("-", "+");
    decodedString = decodedString.replaceAll("_", "/");
    return decodedString;
}



function convertToStringArray (json jsonData) (string[]) {
    string[] outData = [];
    if (lengthof jsonData > 0) {
        int i = 0;
        while (i < lengthof jsonData) {
            outData[i] = jsonData[i].toString();
            i = i + 1;
        }
    } else {
        outData[0] = jsonData.toString();
    }
    return outData;
}
