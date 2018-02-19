import ballerina.auth;
import ballerina.security.jwt;
import ballerina.security.signature;
import ballerina.net.uri;

public function main (string[] args) {
    string jwtToken = "ewogICJhbGciOiAiUlMyNTYiLAogICJ0eXAiOiAiSldUIgp9.ewogICJzdWIiOiAiaXNoYXJhIiwKICAibmFtZSI6ICJKb2huIERvZSIsCiAgImFkbWluIjogdHJ1ZSwKICAiaXNzIjogIndzbzIiLAogICJhdWQiOiAiQmFsbGVyaW5hIiwKICAic2NvcGUiOiAiSm9obiB0ZXN0IERvZSIsCiAgInJvbGVzIjogWyJhZG1pbiIsImFkbWluMiJdLAogICJleHAiOiAxNTE5MDUyNjU5NTcwCn0=.WpUoN4TA0PeisfvbwUuxpsrLXg6jwZ2Iv6EvNkqXR3QQ6FjNGzTizCqdInXE-BDgaCtTJvXq1iqCoRpOo4ORPh5UwiMJKLMRJABT_YVc01_FJO7nNHtQDa1LCehk2BJeZ271f_WTaub9RFch-n4KCJBWufEx7X76OEGErXYdZCI=";
    boolean isVerified;
    error e;
    isVerified, e = jwt:validateJWT(jwtToken);
    //jwt:validateJWT("fdafa");
    println(isVerified);
}

