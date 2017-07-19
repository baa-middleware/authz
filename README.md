# authz
baa  middleware for authorization, it's based on https://github.com/casbin/casbin.

## Use：
```
// Init 
	e := casbin.NewEnforcer("conf/rbac_model.conf", "conf/rbac_policy.csv")
	ini := authz.Config{
		ExcludeURL:    excludeURL,
		ExcludePrefix: excludePrefix,
		Extractor: func(c *baa.Context) (string, error) {
			customs, err := base.GetStandClaims(c)
			if err != nil {
				return "get user Info failure", err
			}
			return strconv.Itoa(customs.Auth.ID), nil
		},
	}
	b.Use(authz.Authorizer(e, ini))
```
## Config：


### ExcludeURL `[]string`
skip authz for these url，for example login or register, /login,/register

### ExcludePrefix `[]string`
skip authz for these url prefix，for example login or register, /login,/register

### Extractor
Custom methods to obtain user information, such as from JWT or session
