import ballerina.auth;
import ballerina.security.jwt;
import ballerina.security.signature;
import ballerina.net.uri;
import ballerina.security.auth.jwtAuthenticator;

public function main (string[] args) {
    string jwtToken = "ewogICJhbGciOiAiUlMyNTYiLAogICJ0eXAiOiAiSldUIgp9.ewogICJzdWIiOiAiaXNoYXJhIiwKICAibmFtZSI6ICJKb2huIERvZSIsCiAgImFkbWluIjogdHJ1ZSwKICAiaXNzIjogIndzbzIiLAogICJhdWQiOiAiQmFsbGVyaW5hIiwKICAic2NvcGUiOiAiSm9obiB0ZXN0IERvZSIsCiAgInJvbGVzIjogWyJhZG1pbiIsImFkbWluMiJdLAogICJleHAiOiAxNTE5MTQwNDA0MDYyCn0=.cPAds8HnoMvPPsmr-U0rcv1kynzMzsHbaM-qSyBlDETwBrBS7Ojj--rExg-PcyE0XBmdF3ChU8R96824ezoPtvD3o6R4cICCDd2dNh4-uVGnvn4BY0t2lDkI9WV1Tu71RSMenAYVF_H_KSanjI51g9fttnVmcXTJJ952CeueUt0=";

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
