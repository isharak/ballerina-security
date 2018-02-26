import ballerina.net.http;
import ballerina.security.auth.jwtAuthenticator;
@http:configuration {
    basePath:"/hello",
    port:9090
}
service<http> helloWorld {
    @http:resourceConfig {
        methods:["GET"],
        path:"/"
    }    resource sayHello (http:Connection conn, http:InRequest req) {

        boolean isAuthenticated = jwtAuthenticator:handle(req);
        http:OutResponse res = {};
        if (isAuthenticated) {
            res.setStringPayload("Successful\n");
        } else {
            res.setStringPayload("Invalid\n");
        }

        _ = conn.respond(res);
    }
}

//curl -H "Authorization: Bearer <ACCESS_TOKEN>" http://localhost:9090/hello

