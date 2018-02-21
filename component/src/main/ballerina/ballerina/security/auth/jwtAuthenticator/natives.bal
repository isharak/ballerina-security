package ballerina.security.auth.jwtAuthenticator;

import ballerina.security.jwt;
import ballerina.config;
import ballerina.caching;
import ballerina.log;

@Description {value:"Represents a JWT Authenticator"}
@Field {value:"jwtValidatorConfig: JWTValidatorConfig object"}
@Field {value:"authCache: Authentication cache object"}
public struct JWTAuthenticator {
    jwt:JWTValidatorConfig jwtValidatorConfig;
    caching:Cache authCache;
}

const string AUTHENTICATOR_JWT = "authenticator_jwt";
const string ISSUER = "issuer";
const string AUDIENCE = "audience";
const string CERTIFICATE_ALIAS = "certificateAlias";
const string JWT_AUTH_CACHE = "jwt_auth_cache";
const string SCOPE = "scope";
const string ROLES = "roles";

struct SecurityContext {
    string userName;
    string[] roles;
    string[] scopes;
    map customClaims;
}

struct CachedSecurityContext {
    SecurityContext securityContext;
    int expiryTime;
}

@Description {value:"Creates a JWT Authenticator instance"}
@Return {value:"JWTAuthenticator instance"}
public function createAuthenticator () (JWTAuthenticator) {
    JWTAuthenticator authenticator = {};
    authenticator.jwtValidatorConfig = getAuthenticatorConfig();
    authenticator.authCache = createCache(JWT_AUTH_CACHE);
    return authenticator;
}

@Description {value:"Authenticate with a jwt token"}
@Param {value:"jwtToken: Jwt token extracted from the authentication header"}
@Return {value:"boolean: true if authentication is a success, else false"}
public function <JWTAuthenticator authenticator> authenticate (string jwtToken) (boolean) {

    boolean isAuthenticated = false;
    SecurityContext securityContext;
    boolean isCacheHit = false;

    if (authenticator.authCache != null) {
        isCacheHit, isAuthenticated, securityContext = authenticator.authenticateFromCache(jwtToken);
        if (isCacheHit) {
            return isAuthenticated;
        }
    }

    var isValid, payload, e = jwt:verify(jwtToken, authenticator.jwtValidatorConfig);

    if (isValid) {
        securityContext = setSecurityContext(payload);
        if (authenticator.authCache != null) {
            authenticator.addToAuthenticationCache(jwtToken, payload.exp, securityContext);
        }
        return true;
    } else {
        if (e != null) {
            log:printErrorCause("Error while validating JWT token ", e);
        }
        return false;
    }
}

function getAuthenticatorConfig () (jwt:JWTValidatorConfig) {
    jwt:JWTValidatorConfig jwtValidatorConfig = {};
    jwtValidatorConfig.issuer = config:getInstanceValue(AUTHENTICATOR_JWT, ISSUER);
    jwtValidatorConfig.audience = config:getInstanceValue(AUTHENTICATOR_JWT, AUDIENCE);
    jwtValidatorConfig.certificateAlias = config:getInstanceValue(AUTHENTICATOR_JWT, CERTIFICATE_ALIAS);
    return jwtValidatorConfig;
}

function <JWTAuthenticator authenticator> authenticateFromCache (string jwtToken) (boolean isCacheHit,
                                                                                   boolean isAuthenticated,
                                                                                   SecurityContext securityContext) {
    var cachedSecurityContext, _ = (CachedSecurityContext)authenticator.authCache.get(jwtToken);
    if (cachedSecurityContext != null) {
        isCacheHit = true;
        if (cachedSecurityContext.expiryTime > currentTime().time) {
            isAuthenticated = true;
            securityContext = cachedSecurityContext.securityContext;
            log:printDebug("Authenticate user :" + securityContext.userName + " from cache");
        }
    }
    return;
}

function <JWTAuthenticator authenticator> addToAuthenticationCache (string jwtToken, int exp, SecurityContext
                                                                                              securityContext) {
    CachedSecurityContext cachedContext = {};
    cachedContext.securityContext = securityContext;
    cachedContext.expiryTime = exp;
    authenticator.authCache.put(jwtToken, cachedContext);
    log:printDebug("Add authenticated user :" + securityContext.userName + " to the cache");
}

function setSecurityContext (jwt:Payload jwtPayload) (SecurityContext) {
    SecurityContext securityContext = {};
    securityContext.userName = jwtPayload.sub;
    if (jwtPayload.customClaims[SCOPE] != null) {
        var scopeString, _ = (string)jwtPayload.customClaims[SCOPE];
        if (scopeString != null) {
            securityContext.scopes = scopeString.split(" ");
        }
    }
    if (jwtPayload.customClaims[ROLES] != null) {
        var roleList, _ = (string[])jwtPayload.customClaims[ROLES];
        if (roleList != null) {
            securityContext.roles = roleList;
        }
    }
    return securityContext;
}


//TODO : use security utils
@Description {value:"Configuration entry to check if a cache is enabled"}
const string CACHE_ENABLED = "enabled";
@Description {value:"Configuration entry for cache expiry time"}
const string CACHE_EXPIRY_TIME = "expiryTime";
@Description {value:"Configuration entry for cache capacity"}
const string CACHE_CAPACITY = "capacity";
@Description {value:"Configuration entry for eviction factor"}
const string CACHE_EVICTION_FACTOR = "evictionFactor";
@Description {value:"Default value for enabling cache"}
const boolean CACHE_ENABLED_DEFAULT_VALUE = true;
@Description {value:"Default value for cache expiry in milliseconds"}
const int CACHE_EXPIRY_DEFAULT_VALUE = 300000;
@Description {value:"Default value for cache capacity"}
const int CACHE_CAPACITY_DEFAULT_VALUE = 100;
@Description {value:"Default value for cache eviction factor"}
const float CACHE_EVICTION_FACTOR_DEFAULT_VALUE = 0.25;

//TODO : Use security utils for this
function isCacheEnabled (string cacheName) (boolean) {
    string isCacheEnabled = config:getInstanceValue(cacheName, CACHE_ENABLED);
    boolean boolIsCacheEnabled;
    if (isCacheEnabled == null) {
        // by default we enable the cache
        boolIsCacheEnabled = CACHE_ENABLED_DEFAULT_VALUE;
    } else {
        TypeConversionError typeConversionErr;
        boolIsCacheEnabled, typeConversionErr = <boolean>isCacheEnabled;
        if (typeConversionErr != null) {
            boolIsCacheEnabled = CACHE_ENABLED_DEFAULT_VALUE;
        }
    }
    return boolIsCacheEnabled;
}

public function createCache (string cacheName) (caching:Cache) {
    if (isCacheEnabled(cacheName)) {
        int expiryTime;
        int capacity;
        float evictionFactor;
        expiryTime, capacity, evictionFactor = getCacheConfigurations(cacheName);
        return caching:createCache(cacheName, expiryTime, capacity, evictionFactor);
    }
    return null;
}

function getCacheConfigurations (string cacheName) (int, int, float) {
    // expiry time
    string expiryTime = config:getInstanceValue(cacheName, CACHE_EXPIRY_TIME);
    int intExpiryTime;
    if (expiryTime == null) {
        // set the default
        intExpiryTime = CACHE_EXPIRY_DEFAULT_VALUE;
    } else {
        TypeConversionError typeConversionErr;
        intExpiryTime, typeConversionErr = <int>expiryTime;
        if (typeConversionErr != null) {
            intExpiryTime = CACHE_EXPIRY_DEFAULT_VALUE;
        }
    }
    // capacity
    string capacity = config:getInstanceValue(cacheName, CACHE_CAPACITY);
    int intCapacity;
    if (capacity == null) {
        intCapacity = CACHE_CAPACITY_DEFAULT_VALUE;
    } else {
        TypeConversionError typeConversionErr;
        intCapacity, typeConversionErr = <int>capacity;
        if (typeConversionErr != null) {
            intCapacity = CACHE_CAPACITY_DEFAULT_VALUE;
        }
    }
    // eviction factor
    string evictionFactor = config:getInstanceValue(cacheName, CACHE_EVICTION_FACTOR);
    float floatEvictionFactor;
    if (evictionFactor == null) {
        floatEvictionFactor = CACHE_EVICTION_FACTOR_DEFAULT_VALUE;
    } else {
        TypeConversionError typeConversionErr;
        floatEvictionFactor, typeConversionErr = <float>evictionFactor;
        if (typeConversionErr != null || floatEvictionFactor > 1.0) {
            floatEvictionFactor = CACHE_EVICTION_FACTOR_DEFAULT_VALUE;
        }
    }

    return intExpiryTime, intCapacity, floatEvictionFactor;
}
