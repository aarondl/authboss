# Config

The config struct is an important part of Authboss. It's the key to making Authboss do what you
want with the implementations you want. Please look at it's code definition as you read the
documentation below, it will make much more sense.

[Config Struct Documentation](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Config)

### Paths

Paths are the paths that should be redirected to or used in whatever circumstance they describe.
Two special paths that are required are `Mount` and `RootURL` without which certain authboss
modules will not function correctly. Most paths get defaulted to `/` such as after login success
or when a user is locked out of their account.

### Modules

Modules are module specific configuration options. They mostly control the behavior of modules.
For example `RegisterPreserveFields` decides a whitelist of fields to allow back into the data
to be re-rendered so the user doesn't have to type them in again.

### Mail

Mail sending related options.

### Storage

These are the implementations of how storage on the server and the client are done in your
app. There are no default implementations for these at this time. See the [Godoc](https://pkg.go.dev/mod/github.com/aarondl/authboss/v3) for more information
about what these are.

### Core

These are the implementations of the HTTP stack for your app. How do responses render? How are
they redirected? How are errors handled?

For most of these there are default implementations from the
[defaults package](https://github.com/aarondl/authboss/tree/master/defaults) available, but not for all.
See the package documentation for more information about what's available.
