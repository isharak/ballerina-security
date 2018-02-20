import ballerina.auth;
import ballerina.security.jwt;
import ballerina.security.signature;
import ballerina.net.uri;
import ballerina.security.auth.jwtAuthenticator;

public function main (string[] args) {
    string jwtToken = "ewogICJhbGciOiAiUlMyNTYiLAogICJ0eXAiOiAiSldUIgp9.ewogICJzdWIiOiAiaXNoYXJhIiwKICAibmFtZSI6ICJKb2huIERvZSIsCiAgImFkbWluIjogdHJ1ZSwKICAiaXNzIjogIndzbzIiLAogICJhdWQiOiAiQmFsbGVyaW5hIiwKICAic2NvcGUiOiAiSm9obiB0ZXN0IERvZSIsCiAgInJvbGVzIjogWyJhZG1pbiIsImFkbWluMiJdLAogICJleHAiOiAxNTE5MTI2NjE3MDkyCn0=.efoBd7mfKeT2XnUmdpIL-s_xlz8Ku9XWWliAzZOIw4GAWPlz4VtBfyqcquhgPM8UMmErFkeF8C3tgkbbqrPh-wNm_eImpBPMwjGW2GfJgl-FM1SGRjKxzOpbhqHmOfBVvQYXbXhyNnieWPZ92f4PMNB1sBjuFE_KwpVw5lOZW1o=";

    boolean isVerified;
    error e;
    jwt:JWTValidatorConfig config = {};
    jwt:Payload payload;
    config.issuer = "wso2";
    config.audience = "Ballerina";
    config.certificateAlias = "wso2carbon";
    isVerified,payload, e = jwt:verify(jwtToken, config);
    //jwt:validateJWT("fdafa");
    jwtAuthenticator:JWTAuthenticator authenticator = jwtAuthenticator:createAuthenticator();
    boolean authenticated = authenticator.authenticate(jwtToken);

    println(isVerified);

    println("Authenticated : " + authenticated);
}

// ballerina run /home/ishara/wso2/ballerina/dev/ballerina-security/component/samples/ballerina/security/jwt/Sample.bal -Bballerina.conf=/home/ishara/wso2/ballerina/dev/ballerina-security/component/samples/resources/ballerina.conf
