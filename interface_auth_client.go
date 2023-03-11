/* Written by Dave Richards.
 *
 * These are the types required to communicate with the authenticator service as a client.
 */
package discodove_interface_auth

import (
	"net/textproto"
)


// For use in requestType in DiscoDoveAuthRequest
const (
	QueryImplements = iota
	PerformAuthentication
)

// For use in authType in DiscoDoveAuthRequest and used in DiscoDoveAuthPlugin.Implements
// If AuthBasicUsernameAndPassword is specified, we will also provide AuthSASLLogin support
// The plugin must explicity implement AuthSASLPlain if the plugin is coded for it.
const (
	AuthBasicUsernameAndPassword = iota
	AuthSASLLogin
	AuthSASLPlain
)

/* Send this down the auth channel to request an authentication via discodove, and it will do the hard
 * work to figure out what plugins to use. 
 * requestType	: from the const's above, either perform an auth, or query
 * authType		: from the const's above, depending on hwhat you would like to offer
 * username 	: username to authenticate
 * password     : passwrod to authenticate
 * commsPort 	: the connection over which to perform some non-username/password authentication, for
 * 				  example SASL Plain
 * responseChan : the channel, of type DiscoDoveAuthResponse, down which the authenticator will send
 * 				  the response - the authenticator will not close this channel.
 */
type DiscoDoveAuthRequest struct {
	RequestType int
	AuthType int
	Username string  
	Password string
	CommsPort *textproto.Conn
	ResponseChan chan DiscoDoveAuthResponse
}

// For use with authResult in DiscoDoveAuthResponse
const (
	AuthOK = iota
	AuthFail
)

/* The authenticators response to your request
 * implements 		: if you queried the auth types implemented, a slice of supported mechanisms using the
 *                    contstants above.
 * authResults 		: the results of a PerformAuthentication request
 * authedUser 		: the user for whom you should assume the session is for - in SASL for example, the 
 *                    authenticated user may not be the session user.
 */
type DiscoDoveAuthResponse struct {
	Implements []int
	AuthResult int
	AuthedUser string
}