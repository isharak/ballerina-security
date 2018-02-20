import ballerina.auth;
import ballerina.security.jwt;
import ballerina.security.signature;
import ballerina.net.uri;

public function main (string[] args) {
    string jwtToken = "ewogICJhbGciOiAiUlMyNTYiLAogICJ0eXAiOiAiSldUIgp9.ewogICJzdWIiOiAiaXNoYXJhIiwKICAibmFtZSI6ICJKb2huIERvZSIsCiAgImFkbWluIjogdHJ1ZSwKICAiaXNzIjogIndzbzIiLAogICJhdWQiOiAiQmFsbGVyaW5hIiwKICAic2NvcGUiOiAiSm9obiB0ZXN0IERvZSIsCiAgInJvbGVzIjogWyJhZG1pbiIsImFkbWluMiJdLAogICJleHAiOiAxNTE5MTA4NjU5NjEyCn0=.bX8_6_to7eWIv-spCN1UzmjS2XhwNJdQU2LZ4bwWTgN1bmEbz0WjGQgvwOFPA2ONhfH1e5EnaETMpRqMgKYQPkFu1kwjlmacedwk0wUpNWfoQnOJDT2vBWEtw6s_B2KzP3oVWyglf4G8wDPOLwpFPcWzl-LQ4nGaTKYOoXKNMRY=";
    boolean isVerified;
    error e;
    isVerified, e = jwt:verify(jwtToken);
    //jwt:validateJWT("fdafa");
    println(isVerified);
}

