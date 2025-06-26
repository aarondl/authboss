# Migrating to v2 from v1

As always, the best way to understand most of this is to look at the
[authboss-sample](https://github.com/aarondl/authboss-sample). You could even look at
the commits that lead from v1 to v2 (though it is not divided nicely into small commits).

## Configuration

The configuration has been changed drastically from an API perspective as it's now sub-divided
with substructs into pieces. But in general the same options should be available with few exceptions.

In most cases the replacements will be very straightforward, and if you were using the default values
nothing much should have to change.

## HTTP Stack (and defaults package)

The HTTP stack has been ripped apart into several small interfaces defined in the config struct.
Before you panic when you see Responder, Redirector, BodyReader etc, it's important to see the
`defaults` package in Authboss. This package contains sane default implementations for all of
these components (with the exception of an html renderer, though a JSON one is present).

You probably will not want to override any of these and so I'd suggest a peek at the method
`default.SetCore` (used in the sample as well) that sets up these default implementations
easily.

There is also an HTML renderer available at
[authboss-renderer](https://github.com/aarondl/authboss-renderer).

## Server storage

### Understanding User vs Storer

In the past Authboss used extremely confusing terminology and sort of a conflated
design of User and Storer (database). In v2 these concepts have been separated and
there is now a User interface and a ServerStorer interface. These two interfaces represent
the concepts of the User data, and the Server storage mechanism that loads and saves
users.

The user interface is now implemented without reflection. Previously in Authboss we would
scrape the values from your struct, and update them via reflection as well. This is extremely
error prone and relies on hardcoded types everywhere and it just generally was a bad idea.
Despite the verbosity of using methods for every single field value we want, it's type safe
and provides a great spot for doing type conversions between whatever you're using in your
struct/database and whatever authboss wants for talking to web clients.

### ServerStorer

This interface simply needs to Load and Save Users at the outset. Just like before there
are upgraded interfaces that are required by other modules, for example the `recover` module
wants a `RecoveringServerStorer` which has the method `LoadByRecoverToken` which you'll have
to add to your storer.

### User

Your user struct should be able to remain the same, and all you need to do is add the methods
required for getting and setting the fields. Remember the methods are dictated by the interfaces
required by the modules you're loading (see authboss README.md for more details). For example
the `auth` module requires an `AuthableUser` which requires `Get|PutPassword` methods.

## Client state

The client state interfaces have been rewritten to do a just-in-time write to the response
before the headers are completely flushed. This makes sure we only Read and only Write the
client state (cookies/sessions) one time. It requires a new middleware `LoadClientStateMiddleware`
which wraps the responsewriter with a new one that has the ability to manage client state.

In the ClientStateReadWriter interface (the one you now implement to handle sessions and cookies)
you now return a ClientState interface (basically a map of values) that represents a snapshot of the
state of the client when the request was initially read, this ensures that code will use the context
for value passing through the middleware stack and not the session as an added bonus.
Essentially this ClientState caches the values for the remainder of the request.

Events are written to the ResponseWriter and eventually the `WriteState` method is called and is
given the old state and the events that occurred during request processing, asks for a new state
to be written out to the responsewriter's headers.
