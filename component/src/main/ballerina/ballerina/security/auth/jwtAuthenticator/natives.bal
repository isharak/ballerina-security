package ballerina.security.auth.jwtAuthenticator;

import ballerina.security.jwt;
import ballerina.config;

const string AUTHENTICATOR_JWT = "authenticator_jwt";
const string ISSUER = "issuer";
const string AUDIENCE = "audience";
const string CERTIFICATE_ALIAS = "certificateAlias";


const string scope = "scope";
const string roles = "roles";


@Description {value:"Represents a JWT Authenticator"}
@Field {value:"jwtValidatorConfig: JWTValidatorConfig object"}
public struct JWTAuthenticator {
    jwt:JWTValidatorConfig jwtValidatorConfig;
}

struct SecurityContext {
    string userName;
    string[] roles;
    string[] scopes;
    map customClaims;
}

@Description {value:"Creates a JWT Authenticator"}
@Return {value:"JWTAuthenticator instance"}
public function createAuthenticator () (JWTAuthenticator) {
    JWTAuthenticator authenticator = {};
    authenticator.jwtValidatorConfig = getAuthenticatorConfig();
    return authenticator;
}

@Description {value:"Authenticate with a jwt token"}
@Param {value:"jwtToken: Jwt token extracted from the authentication header"}
@Return {value:"boolean: true if authentication is a success, else false"}
public function <JWTAuthenticator authenticator> authenticate (string jwtToken) (boolean) {
    boolean isValid;
    error e;
    jwt:Payload payload;
    isValid, payload, e = jwt:verify(jwtToken, authenticator.jwtValidatorConfig);

    if (isValid) {
        SecurityContext securityContext = setSecurityContext(payload);
        println(securityContext.userName);
        return true;
    } else {
        return false;
    }
}

function getAuthenticatorConfig () (jwt:JWTValidatorConfig) {
    jwt:JWTValidatorConfig jwtValidatorConfig = {};
    jwtValidatorConfig.issuer = config:getInstanceValue(AUTHENTICATOR_JWT, ISSUER);
    jwtValidatorConfig.audience = config:getInstanceValue(AUTHENTICATOR_JWT, AUDIENCE);
    jwtValidatorConfig.certificateAlias = config:getInstanceValue(AUTHENTICATOR_JWT, CERTIFICATE_ALIAS);
    return jwtValidatorConfig;
}

function setSecurityContext (jwt:Payload jwtPayload) (SecurityContext) {
    SecurityContext authenticatedUser = {};
    authenticatedUser.userName = jwtPayload.sub;
    if (jwtPayload.customClaims[scope] != null) {
        var scopeString, _ = (string)jwtPayload.customClaims[scope];
        if (scopeString != null) {
            authenticatedUser.scopes = scopeString.split(" ");
        }
    }
    if (jwtPayload.customClaims[roles] != null) {
        var roleList, _ = (string[])jwtPayload.customClaims[roles];
        if (roleList != null) {
            authenticatedUser.roles = roleList;
        }
    }
    return authenticatedUser;
}