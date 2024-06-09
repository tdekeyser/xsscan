// Check for origin misconfiguration, such as Access-Control-Allow-Origin: *
// See https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSMissingAllowOrigin

//  To allow any site to make CORS requests without using the * wildcard
// (for example, to enable credentials), your server must read the value of the request's
// Origin header and use that value to set Access-Control-Allow-Origin, and must also set
// a Vary: Origin header to indicate that some headers are being set dynamically depending
// on the origin.
