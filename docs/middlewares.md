# Middlewares

The only middleware that's truly required is the `LoadClientStateMiddleware`, and that's because it
enables session and cookie handling for Authboss. Without that, it's not a very useful piece of
software.

The remaining middlewares are either the implementation of an entire module (like expire),
or a key part of a module. For example you probably wouldn't want to use the lock module
without the middleware that would stop a locked user from using an authenticated resource,
because then locking wouldn't be useful unless of course you had your own way of dealing
with locking, which is why it's only recommended, and not required. Typically you will
use the middlewares if you use the module.

Name | Requirement | Description
---- | ----------- | -----------
[Middleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Middleware) | Recommended | Prevents unauthenticated users from accessing routes.
[LoadClientStateMiddleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Authboss.LoadClientStateMiddleware) | **Required** | Enables cookie and session handling
[ModuleListMiddleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Authboss.ModuleListMiddleware) | Optional | Inserts a loaded module list into the view data
[confirm.Middleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/confirm/#Middleware) | Recommended with confirm | Ensures users are confirmed or rejects request
[expire.Middleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/expire/#Middleware) | **Required** with expire | Expires user sessions after an inactive period
[lock.Middleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/lock/#Middleware) | Recommended with lock | Rejects requests from locked users
[remember.Middleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/remember/#Middleware) | Recommended with remember | Logs a user in from a remember cookie