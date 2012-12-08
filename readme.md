# WordPress OAuth Provider
This is a WordPress plugin to enable your WordPress installation to act as an
OAuth provider. This plugin is an internal plugin, in that you need to add most
of the relevant OAuth endpoints yourself, with only user-facing pages set up.

This plugin is best used in conjunction with an API server linked into
WordPress, enabling use of the API server via OAuth authentication.


## Usage
See `example-implementer.php`


## License
This project is licensed under the new BSD license, and is copyright 2012 Ryan
McCue.


## Internals
The OAuth tokens and nonces are stored using the WordPress transient and option
APIs, enabling easy integration with existing object caching solutions, such as
APC and memcache.

- Tokens
	- Request tokens: Prefixed with `wpoa_rt_`, stored as transients
	- Access tokens: Prefixed with `wpoa_at_`, stored as options
- Nonces: Prefixed with `wpoa_n_`


## FAQ

### Why is this totally broken?
Are you using APC with an object caching plugin? Check that it's up-to-date, as
older versions of APC have a bug which will break this plugin.
