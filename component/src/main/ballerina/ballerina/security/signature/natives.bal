package ballerina.security.signature;

@Description {value:"Verify the signature of a given string"}
@Param {value:"data: Original data which has signed."}
@Param {value:"signature: Signature string."}
@Param {value:"signature: Signature algorithm."}
@Return {value:"verified status. true or false"}
public native function verify(string data, string signature, string algorithm) (boolean);