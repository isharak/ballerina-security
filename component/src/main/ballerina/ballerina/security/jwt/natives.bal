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

public function validateJWT(string jwtToken) (boolean){

    string[] encodedJWTComponents = getJWTComponents(sampleJWTToken);

    //TODO need to do the decoding parts of header and body (Base64URL decode is not yet implemented)
    //TODO then need to convert header data from UTF-8 to char set which is used in current version
    string jwtHeader = util:base64Encode(getJWTHeader());
    string jwtPayload = util:base64Encode(getJWTPayload());

    var jwtHeaderJson, _ = <json>jwtHeader;
    var jwtPayloadJson, _ = <json>jwtPayload;

    map customClaims = {};
    foreach k in jwtPayloadJson.getKeys() {
        string key = <string>k;
        if (key.equalsIgnoreCase(iss)) {
            //Validate each element
        } else if (key.equalsIgnoreCase(sub)) {

        } else if (key.equalsIgnoreCase(aud)) {

        } else if (key.equalsIgnoreCase(jti)) {

        } else if (key.equalsIgnoreCase(exp)) {

        } else if (key.equalsIgnoreCase(nbf)) {

        } else if (key.equalsIgnoreCase(iat)) {

        }
        else {
            customClaims[key] = <string>jwtPayloadJson[key];
        }
    }

    string assertion = encodedJWTComponents[0] + "." + encodedJWTComponents[1];
    string signPart = encodedJWTComponents[2];
    //string decodedSignPart = util:base64Decode(signPart);
    return signature:verify(assertion, signPart, "RS256");

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
