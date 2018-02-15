package ballerina.security.jwt;

import ballerina.util;
import ballerina.security.signature;

public function validateJWT(string jwtToken) (boolean){
    string[] jwtComponents = jwtToken.split("\\.");
    string assertion = jwtComponents[0] + "." + jwtComponents[1];
    string signPart = jwtComponents[2];
    //string decodedSignPart = util:base64Decode(signPart);
    return signature:verify(assertion, signPart, "RS256");

    //String algorithm = "SHA256withRSA";
    //String[] jwtComponents = jwt.split("\\.");
    //String assersion = jwtComponents[0] + "." + jwtComponents[1];
    //String signPart = jwtComponents[2];
    //byte[] signData = Base64.getUrlDecoder().decode(signPart);
    //return verifySignature(assersion.getBytes(), signData, algorithm);

}

