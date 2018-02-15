import ballerina.auth;
import ballerina.security.jwt;
import ballerina.security.signature;
import ballerina.net.uri;

public function main (string[] args) {

    string jwtToken ="eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSIsImlzcyI6Imh0dHBzOlwvXC9jMmlkLmNvbSIsImlhdCI6MTQxNjE1ODU0MX0.iTf0eDBF-6-OlJwBNxCK3nqTUjwC71-KpqXVr21tlIQq4_ncoPODQxuxfzIEwl3Ko_Mkt030zJs-d36J4UCxVSU21hlMOscNbuVIgdnyWhVYzh_-v2SZGfye9GxAhKOWL-_xoZQCRF9fZ1j3dWleRqIcPBFHVeFseD_64PNemyg";

    //println(auth:authenticate("test"));
    boolean isVerified = jwt:validateJWT(jwtToken);
    println(isVerified);
}

