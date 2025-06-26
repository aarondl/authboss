# Rendering

The authboss rendering system is simple. It's defined by one interface: [Renderer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Renderer)

The renderer knows how to load templates, and how to render them with some data and that's it.
So let's examine the most common view types that you might want to use.

### HTML Views

When your app is a traditional web application and is generating it's HTML
serverside using templates this becomes a small wrapper on top of your rendering
setup. For example if you're using `html/template` then you could just use
`template.New()` inside the `Load()` method and store that somewhere and call
`template.Execute()` in the `Render()` method.

There is also a very basic renderer: [Authboss
Renderer](https://github.com/aarondl/authboss-renderer) which has some very
ugly built in views and the ability to override them with your own if you don't
want to integrate your own rendering system into that interface.

### JSON Views

If you're building an API that's mostly backed by a javascript front-end, then you'll probably
want to use a renderer that converts the data to JSON. There is a simple json renderer available in
the [defaults package](https://github.com/aarondl/authboss/tree/master/defaults) package if you wish to
use that.

### Data

The most important part about this interface is the data that you have to render.
There are several keys that are used throughout authboss that you'll want to render in your views.

They're in the file [html_data.go](https://github.com/aarondl/authboss/blob/master/html_data.go)
and are constants prefixed with `Data`. See the documentation in that file for more information on
which keys exist and what they contain.

The default [responder](https://pkg.go.dev/github.com/aarondl/authboss/v3/defaults/#Responder)
also happens to collect data from the Request context, and hence this is a great place to inject
data you'd like to render (for example data for your html layout, or csrf tokens).