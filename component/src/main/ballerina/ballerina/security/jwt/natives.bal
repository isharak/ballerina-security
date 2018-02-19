package ballerina.security.jwt;

import ballerina.util;
import ballerina.security.signature;

//JOSH header parameters
const string alg = "alg";

//Payload parameters
const string iss = "iss";
const string sub = "sub";
const string aud = "aud";
const string jti = "jti";
const string exp = "exp";
const string nbf = "nbf";
const string iat = "iat";

struct JWTPayload {
    string iss;
    string sub;
    string[] aud;
    string jti;
    int exp;
    int nbf;
    int iat;
    map customClaims;

}

struct SecurityContext {
    string userName;
    string[] roles;
    string[] scopes;
    string[] clims;
}

public function validateJWT (string jwtToken) (boolean, error) {

    string[] encodedJWTComponents = getJWTComponents(sampleJWTToken);

    //TODO need to do the decoding parts of header and body (Base64URL decode is not yet implemented)
    //TODO then need to convert header data from UTF-8 to char set which is used in current version
    string jwtHeader = util:base64Encode(encodedJWTComponents[0]);
    string jwtPayload = util:base64Encode(encodedJWTComponents[1]);

    var jwtHeaderJson, _ = <json>jwtHeader;
    var jwtPayloadJson, _ = <json>jwtPayload;

    JWTPayload jwtPayload = processJWTPayload(jwtPayloadJson);
    validateJWT(encodedJWTComponents, jwtPayload, jwtHeaderJson);


    string assertion = encodedJWTComponents[0] + "." + encodedJWTComponents[1];
    string signPart = encodedJWTComponents[2];
    return signature:verify(assertion, signPart, jwtHeaderJson.alg), null;

}

function getJWTComponents (string jwtToken) (string[]) {
    string[] jwtComponents = jwtToken.split("\\.");
    //if(lengthof jwtComponents != 3){
    //    //TODO Need to return error.
    //    }
    //string dataPart = jwtComponents[0] + "." + jwtComponents[1];
    //string signature = jwtComponents[2];
    return jwtComponents;

}

function processJWTPayload (json jwtPayloadJson) (JWTPayload) {
    JWTPayload jwtPayload = {};

    map customClaims = {};
    foreach k in jwtPayloadJson.getKeys() {
        string key = <string>k;
        //println(typeof jwtPayloadJson[key] );
        var value = jwtPayloadJson[key].toString();
        if (key.equalsIgnoreCase(iss)) {
            jwtPayload.iss = value;
        } else if (key.equalsIgnoreCase(sub)) {
            jwtPayload.sub = value;
        } else if (key.equalsIgnoreCase(aud)) {
            string[] audienceList = [];
            if (lengthof jwtPayloadJson[key] > 0) {
                int i = 0;
                while (i < lengthof jwtPayloadJson[key]) {
                    audienceList[i] = jwtPayloadJson[key][i].toString();
                    i = i + 1;
                }
            } else {
                audienceList[0] = value;
            }
            jwtPayload.aud = audienceList;
        } else if (key.equalsIgnoreCase(jti)) {
            jwtPayload.jti = value;
        } else if (key.equalsIgnoreCase(exp)) {
            var intVal, _ = <int>value;
            jwtPayload.exp = intVal;
        } else if (key.equalsIgnoreCase(nbf)) {
            var intVal, _ = <int>value;
            jwtPayload.nbf = intVal;
        } else if (key.equalsIgnoreCase(iat)) {
            var intVal, _ = <int>value;
            jwtPayload.iat = intVal;
        }
        else {
            customClaims[key] = jwtPayloadJson[key];
        }
    }
    jwtPayload.customClaims = customClaims;
    return jwtPayload;

}

function validateJWT (string[] encodedJWTComponents, JWTPayload jwtPayload, json jwtHeaderJson) (boolean, error) {
    if (!validateMandatoryFileds(jwtPayload)) {
        error err = {msg:"Mandatory fields(Issuer, Subject, Expiration time or Audience) are empty in the given JSON Web Token."};
        return false, err;
    }
    if (!validateSignature(encodedJWTComponents, jwtHeaderJson)) {
        error err = {msg:"Invalide signature"};
        return false, err;
    }
    if (!validateIssuer(jwtPayload)) {
        error err = {msg:"No Registered IDP found for the JWT with issuer name : " + jwtPayload.iss};
        return false, err;
    }
    if (!validateAudience(jwtPayload)) {
        error err = {msg:"Invalide audience : " + jwtPayload.aud};
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

    //TODO
    //validateJWTId();
    //validateCustomClaims();

    return true, null;


}

function validateMandatoryFileds (JWTPayload jwtPayload) (boolean) {
    if (jwtPayload.iss == null || jwtPayload.sub == null || jwtPayload.exp == 0 || jwtPayload.aud == null) {
        return false;
    }
    return true;
}

function validateSignature (string[] encodedJWTComponents, json jwtHeaderJson) (boolean) {
    //TODO validate the signature
    return true;
}

function validateIssuer (JWTPayload jwtPayload) (boolean) {
    return jwtPayload.iss.equalsIgnoreCase(getJWTAuthConfiguration(iss));
}

function validateAudience (JWTPayload jwtPayload) (boolean) {
    foreach audince in jwtPayload.aud {
        if (audince.equalsIgnoreCase(getJWTAuthConfiguration(aud))) {
            return true;
        }
        return false;
    }
}

function validateExpirationTime (JWTPayload jwtPayload) (boolean) {
    return jwtPayload.exp > currentTime().time;
}

function validateNotBeforeTime (JWTPayload jwtPayload) (boolean) {
    return currentTime().time > jwtPayload.nbf;
}

function getJWTAuthConfiguration (string key) (string) {
    //TODO validate the input and return relevant parameter
    return key;
}

