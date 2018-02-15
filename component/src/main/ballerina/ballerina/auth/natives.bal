package ballerina.auth;

import ballerina.net.http;

@Description {value:"Struct represents the authenticated user context"}
@Field {value:"userID: Unique identifier for user"}
@Field {value:"userName: Human readable unique name"}
@Field {value:"authenticated: Authenticated status"}

public struct User {
    string userID;
    string userName;
    boolean authenticated;
}

public native function authenticate (string val) (string);
public native function validateRequest(http:InRequest req) (string);
public native function authentiacteWithContext(string val) (User);

public function getUserName ()(string )  {
    return "Ishara";
}