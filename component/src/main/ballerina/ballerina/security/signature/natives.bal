package ballerina.security.signature;

@Description {value:"Verify the signature of a given string"}
@Param {value:"data: Original data which has signed."}
@Param {value:"signature: Signature string."}
@Param {value:"algorithm: Signature algorithm."}
@Param {value:"keyAlias: Public key alias. If this is null use default public key."}
@Return {value:"verified status. true or false"}
public native function verify(string data, string signature, string algorithm, string keyAlias) (boolean);

@Description {value:"Sign the given input data"}
@Param {value:"data: Original that need to sign."}
@Param {value:"algorithm: Signature string."}
@Param {value:"keyAlias: Private key alias. If this is null use default private key."}
@Return {value:"signature. Signed string"}
public native function sign(string data, string algorithm, string keyAlias) (string);