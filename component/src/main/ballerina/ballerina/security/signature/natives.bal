package ballerina.security.signature;

@Description {value:"Verify the signature of a given string"}
@Param {value:"data: Original data which has signed."}
@Param {value:"signature: Signature string."}
@Param {value:"algorithm: Signature algorithm."}
@Return {value:"verified status. true or false"}
public native function verify(string data, string signature, string algorithm) (boolean);

@Description {value:"Sign the given input data"}
@Param {value:"data: Original that need to sign."}
@Param {value:"algorithm: Signature string."}
@Return {value:"signature. Signed string"}
public native function sign(string data, string algorithm) (string);