// authz - ACL/RBAC/ABAC authorization based on Casbin for baa
package authz

import (
	"net/http"
	"strings"

	"github.com/casbin/casbin"
	baa "gopkg.in/baa.v1"
)

var (
	// DefaultNoPermString defaut anthz failure err info
	DefaultNoPermString = "You have no permission to visit this api"
	// DefaultNotExtractorString defaut not set up user info extractor
	DefaultNotExtractorString = "You not set up user info extractor"
)

// anytime an error occur ，this function will execute
type errorHandler func(c *baa.Context, err string)

// authInfoExtractor extract user info
type authInfoExtractor func(c *baa.Context) (string, error)

//Config authz config
type Config struct {
	ErrorHandler errorHandler
	// Extractor extract user info for authz
	Extractor authInfoExtractor
	// ExcludeURL exclude url will skip jwt validator
	ExcludeURL []string
	// ExcludePrefix exclude url prefix will skip jwt validator
	ExcludePrefix []string
}

// the default anthz failure function
func onError(c *baa.Context, err string) {
	// authz failure
	c.Resp.WriteHeader(http.StatusForbidden)
	c.Resp.Write([]byte(err))
}

// Authorizer returns a Casbin authorizer Handler.
func Authorizer(e *casbin.Enforcer, config Config) baa.HandlerFunc {
	if config.ErrorHandler == nil {
		config.ErrorHandler = onError
	}
	if config.Extractor == nil {
		panic(DefaultNotExtractorString)
	}

	return func(c *baa.Context) {
		// pre handler
		// skip cors prelight
		if c.Req.Method == "OPTIONS" {
			c.Next()
			return
		}

		// check exclude url
		if len(config.ExcludeURL) > 0 {
			for _, url := range config.ExcludeURL {
				if url == c.Req.URL.Path {
					c.Next()
					return
				}
			}
		}
		// check exclude url prefix
		if len(config.ExcludePrefix) > 0 {
			for _, prefix := range config.ExcludePrefix {
				if strings.HasPrefix(c.Req.URL.Path, prefix) {
					c.Next()
					return
				}
			}
		}

		// get info for anthz
		user, err := config.Extractor(c)
		if err != nil {
			config.ErrorHandler(c, DefaultNoPermString)
		}
		obj := c.RouteName()
		act := strings.ToLower(c.Req.Method)

		if e.Enforce(user, obj, act) {
			c.Next()
		} else {
			config.ErrorHandler(c, DefaultNoPermString)
		}
	}
}
