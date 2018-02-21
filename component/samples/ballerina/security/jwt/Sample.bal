import ballerina.auth;
import ballerina.security.jwt;
import ballerina.security.signature;
import ballerina.net.uri;
import ballerina.security.auth.jwtAuthenticator;

public function main (string[] args) {
    string jwtToken = "ewogICJhbGciOiAiUlMyNTYiLAogICJ0eXAiOiAiSldUIgp9.ewogICJzdWIiOiAiaXNoYXJhIiwKICAibmFtZSI6ICJKb2huIERvZSIsCiAgImFkbWluIjogdHJ1ZSwKICAiaXNzIjogIndzbzIiLAogICJhdWQiOiAiQmFsbGVyaW5hIiwKICAic2NvcGUiOiAiSm9obiB0ZXN0IERvZSIsCiAgInJvbGVzIjogWyJhZG1pbiIsImFkbWluMiJdLAogICJleHAiOiAxNTE5MjExNzg3MzMwCn0=.hnMDSmvJVNOE611qeuTWlSwFsapCnzruWItKbNYCXFCT8rwBa-cu0UkgIxfPBfGIBeIHKKWd1TdntooPrjIYWowV8cwJUvyHfvFSM1yFmtLG6qVmQ9oA83Zm7vZ__Fh07kiAlMNT7DXgy2YlVYgKQY8s8JjvKt-MVHa53kaSg1w=";

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
