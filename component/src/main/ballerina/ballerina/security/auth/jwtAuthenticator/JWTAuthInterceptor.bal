package ballerina.security.auth.jwtAuthenticator;

import ballerina.net.http;
import ballerina.log;

@Description {value:"Authentication header name"}
const string AUTH_HEADER = "Authorization";
@Description {value:"Bearer authentication scheme"}
const string AUTH_SCHEME = "Bearer";

@Description {value:"JWT authenticator instance"}
JWTAuthenticator authenticator;

@Description {value:"Intercepts a request for authentication"}
@Param {value:"req: InRequest object"}
@Return {value:"boolean: true if authentication is a success, else false"}
public function handle (http:InRequest req) (boolean) {
    if (authenticator == null) {
        authenticator = createAuthenticator();
    }
    var token, e = extractJWTToken(req);
    if (e != null) {
        log:printError("Error while authentication ", e);
    }
    return authenticator.authenticate(token);
}

function extractJWTToken (http:InRequest req) (string, error) {
    string authHeader = req.getHeader(AUTH_HEADER);
    if (authHeader == null || !authHeader.hasPrefix(AUTH_SCHEME)) {
        error err = {msg:"Authentication header not sent with the request"};
        return null, err;
    }
    string[] authHeaderComponents = authHeader.split(" ");
    if (lengthof authHeaderComponents != 2) {
        error err = {msg:"Invalid authentication header"};
        return null, err;
    }
    return authHeaderComponents[1], null;
}
