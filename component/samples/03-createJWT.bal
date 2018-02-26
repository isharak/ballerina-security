import ballerina.security.jwt;


public function main (string[] args) {

    jwt:Header header = {};
    header.alg = "RS256";
    header.typ = "JWT";

    jwt:Payload payload = {};
    payload.sub = "ishara";
    payload.iss = "wso2";
    payload.aud = ["ballerina", "wso2Samples"];
    payload.exp = 122222222222;

    jwt:JWTIssuerConfig config = {};
    config.certificateAlias = "wso2carbon";
    var jwt,_ =jwt:createJWT(header, payload, config);

    println(jwt);

}
