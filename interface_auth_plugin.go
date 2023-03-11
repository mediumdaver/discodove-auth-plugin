/* Written by Dave Richards.
 *
 * This is the top-level plugin interface, where you produce a new instance of an authenticator.
 */
package discodove_interface_auth

import (
	"log/syslog"
	"github.com/spf13/viper"
)
  
type DiscoDoveAuthPlugin interface { 

	/* This will be called once when we load this plugin, if you feel compelled to set something up, perhaps a 
	 * control/query/admin thread or something, then do it here in a controlled manner - similarly if 
	 * you want to pool connections, etc....  We assume that each plugin can scale itself, we do no magic
	 * to allow for scalability, so you might want some worker threads.
	 *
	 * Each plugin is responsible for creating it's own syslog connection as *syslog.Writer has a mutex, and 
	 * I don't want the auth threads to be blocking on writing to syslog - so you need to scale logging yourself.
	 * 
	 * We use Viper for config, and you will be passed the config directives for your module, but as it's viper you
	 * can access the entire discodove config too.  Feel free to specify your own config directives.
	 *
	 * name	 	: will be the name of the process, in 99.999% of cases it will just be "discodove" - please
	 *            prefix your log messages with this and perhaps your own identifier e.g. "ldapauth"
	 * syslogFacility : which facility to use in syslog.
	 * conf: a Viper subtree configuration for this service as specified in the discodove config.
	 */
	Initialize(name string, syslogFacility syslog.Priority, conf *viper.Viper) error

	/* This functions is used to determine which authentication methods will be offered by this plugin, 
	 * using the constants specified above to check availability.  This function is used for efficiency
	 * when determining if this plugin will even be consulted when a specific authentication method is requested
	 * by a client.
	 * Example return: [AuthBasicUsernameAndPassword, AuthSASLPlain]
	 */
	Implements() []int

	/* These are the interfaces you need to implement if you support those authentication types.
	 * return the authenticated username on success, on fail return blank and set error. You should
	 * expect many concurrent calls (as go routines) of these functions.
	 *
	 * The authenticating user is authzid, and if authcid is blank then it should be ignored.  However,
	 * if authcid is not blank, the plugin should assess if the authzid user is allowed to authenticate
	 * a session for authcid.  See the SASL PLAIN method for more details.  
	 */
	AuthBasicUsernamePassword(authcid string, authzid string, password string) (string, error)
}
