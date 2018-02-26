import ballerina.security.auth.jwtAuthenticator;

public function main (string[] args) {
    string jwtToken = "ewogICJhbGciOiAiUlMyNTYiLAogICJ0eXAiOiAiSldUIgp9.ewogICJzdWIiOiAiaXNoYXJhIiwKICAibmFtZSI6ICJKb2huIERvZSIsCiAgImFkbWluIjogdHJ1ZSwKICAiaXNzIjogIndzbzIiLAogICJhdWQiOiAiQmFsbGVyaW5hIiwKICAic2NvcGUiOiAiSm9obiB0ZXN0IERvZSIsCiAgInJvbGVzIjogWyJhZG1pbiIsImFkbWluMiJdLAogICJleHAiOiAxNTE5MjExNzg3MzMwCn0=.hnMDSmvJVNOE611qeuTWlSwFsapCnzruWItKbNYCXFCT8rwBa-cu0UkgIxfPBfGIBeIHKKWd1TdntooPrjIYWowV8cwJUvyHfvFSM1yFmtLG6qVmQ9oA83Zm7vZ__Fh07kiAlMNT7DXgy2YlVYgKQY8s8JjvKt-MVHa53kaSg1w=";
    jwtAuthenticator:JWTAuthenticator authenticator = jwtAuthenticator:createAuthenticator();
    boolean authenticated = authenticator.authenticate(jwtToken);
    println("Authenticated : " + authenticated);
}

// ballerina run /home/ishara/wso2/ballerina/dev/ballerina-security/component/samples/ballerina/security/jwt/01-validateJWT.bal -Bballerina.conf=/home/ishara/wso2/ballerina/dev/ballerina-security/component/samples/resources/ballerina.conf
