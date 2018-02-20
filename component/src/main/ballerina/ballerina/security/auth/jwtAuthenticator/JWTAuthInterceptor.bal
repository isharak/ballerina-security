package ballerina.security.auth.jwtAuthenticator;

import ballerina.net.http;

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
    var token, e = extractAuthHeaderValue(req);
    return authenticator.authenticate(token);
}

@Description {value:"Extracts the authentication header value from the request"}
@Param {value:"req: Inrequest instance"}
@Return {value:"string: value of the jwt token"}
@Return {value:"error: any error occurred while extracting the jwt token"}
public function extractAuthHeaderValue (http:InRequest req) (string, error) {

    string authHeader = req.getHeader(AUTH_HEADER);
    if (authHeader == null || !authHeader.hasPrefix(AUTH_SCHEME)) {
        error err = {msg:"Authentication header not sent with the request"};
        return null, err;
    }
    string[] authHeaderComponents = authHeader.split(" ");
    return authHeaderComponents[1], null;
}
