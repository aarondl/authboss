package authboss

import (
	"fmt"
	"github.com/friendsofgo/errors"
	"net/http"
)

//go:generate stringer -output stringers.go -type "Event"

// Event type is for describing events
type Event int

var ErrHalt = fmt.Errorf("event halt")

// Event kinds
const (
	EventRegister Event = iota
	EventAuth
	// EventAuthHijack is used to steal the authentication process after a
	// successful auth but before any session variable has been put in.
	// Most useful for defining an additional step for authentication
	// (like 2fa). It needs to be separate to EventAuth because other modules
	// do checks that would also interrupt event handlers with an authentication
	// failure so there's an ordering problem.
	EventAuthHijack
	EventOAuth2
	EventAuthFail
	EventOAuth2Fail
	EventRecoverStart
	EventRecoverEnd
	EventGetUser
	EventGetUserSession
	// Deprecated: EventPasswordReset is used nowhere
	EventPasswordReset
	EventLogout
	EventTwoFactorAdded
	EventTwoFactorRemoved
)

// EventHandler reacts to events that are fired by Authboss controllers.
// These controllers will normally process a request by themselves, but if
// there is special consideration for example a successful login, but the
// user is locked, the lock module's controller may seize control over the
// request.
//
// Very much a controller level middleware.
type EventHandler func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error)

// Events is a collection of Events that fire before and after certain methods.
type Events struct {
	before map[Event][]EventHandler
	after  map[Event][]EventHandler
}

// NewEvents creates a new set of before and after Events.
func NewEvents() *Events {
	return &Events{
		before: make(map[Event][]EventHandler),
		after:  make(map[Event][]EventHandler),
	}
}

// Before event, call f.
func (c *Events) Before(e Event, f EventHandler) {
	events := c.before[e]
	events = append(events, f)
	c.before[e] = events
}

// After event, call f.
func (c *Events) After(e Event, f EventHandler) {
	events := c.after[e]
	events = append(events, f)
	c.after[e] = events
}

// FireBefore executes the handlers that were registered to fire before
// the event passed in.
//
// If it encounters an error it will stop immediately without calling
// other handlers.
//
// If a handler handles the request, it will pass this information both
// to handlers further down the chain (to let them know that w has been used)
// as well as set w to nil as a precaution.
func (c *Events) FireBefore(e Event, w http.ResponseWriter, r *http.Request) (bool, error) {
	return c.call(c.before[e], w, r)
}

// FireAfter event to all the Events with a context. The error can safely be
// ignored as it is logged.
func (c *Events) FireAfter(e Event, w http.ResponseWriter, r *http.Request) (bool, error) {
	return c.call(c.after[e], w, r)
}

func (c *Events) call(evs []EventHandler, w http.ResponseWriter, r *http.Request) (bool, error) {
	handled := false

	for _, fn := range evs {
		interrupt, err := fn(w, r, handled)
		if err != nil {
			if errors.Is(err, ErrHalt) {
				if interrupt {
					handled = true
				}
				break
			}

			return false, err
		}
		if interrupt {
			handled = true
		}
	}

	return handled, nil
}
