package authboss

import (
	"net/http"
	"testing"

	"github.com/friendsofgo/errors"
)

func TestEvents(t *testing.T) {
	t.Parallel()

	ab := New()
	afterCalled := false
	beforeCalled := false

	ab.Events.Before(EventRegister, func(http.ResponseWriter, *http.Request, bool) (bool, error) {
		beforeCalled = true
		return false, nil
	})
	ab.Events.After(EventRegister, func(http.ResponseWriter, *http.Request, bool) (bool, error) {
		afterCalled = true
		return false, nil
	})

	if beforeCalled || afterCalled {
		t.Error("Neither should be called.")
	}

	handled, err := ab.Events.FireBefore(EventRegister, nil, nil)
	if err != nil {
		t.Error("Unexpected error:", err)
	}
	if handled {
		t.Error("It should not have been handled.")
	}

	if !beforeCalled {
		t.Error("Expected before to have been called.")
	}
	if afterCalled {
		t.Error("Expected after not to be called.")
	}

	ab.Events.FireAfter(EventRegister, nil, nil)
	if !afterCalled {
		t.Error("Expected after to be called.")
	}
}

func TestEventsHandled(t *testing.T) {
	t.Parallel()

	ab := New()
	firstCalled := false
	secondCalled := false

	firstHandled := false
	secondHandled := false

	ab.Events.Before(EventRegister, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
		firstCalled = true
		firstHandled = handled
		return true, nil
	})
	ab.Events.Before(EventRegister, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
		secondCalled = true
		secondHandled = handled
		return false, nil
	})

	handled, err := ab.Events.FireBefore(EventRegister, nil, nil)
	if err != nil {
		t.Error("Unexpected error:", err)
	}
	if !handled {
		t.Error("it should have been handled")
	}

	if !firstCalled {
		t.Error("expected first to have been called")
	}
	if !secondCalled {
		t.Error("expected second to have been called")
	}

	if firstHandled {
		t.Error("first should not see the event as being handled")
	}
	if !secondHandled {
		t.Error("second should see the event as being handled")
	}
}

func TestEventsHaltHandled(t *testing.T) {
	t.Parallel()

	ab := New()
	firstCalled := false
	secondCalled := false

	firstHandled := false
	secondHandled := false

	ab.Events.Before(EventRegister, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
		firstCalled = true
		firstHandled = handled
		return true, ErrHalt
	})
	ab.Events.Before(EventRegister, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
		secondCalled = true
		secondHandled = handled
		return false, nil
	})

	handled, err := ab.Events.FireBefore(EventRegister, nil, nil)
	if err != nil {
		t.Error("Unexpected error:", err)
	}
	if !handled {
		t.Error("it should have been handled")
	}

	if !firstCalled {
		t.Error("expected first to have been called")
	}
	if firstHandled {
		t.Error("first should not see the event as being handled")
	}

	if secondCalled {
		t.Error("expected second to not have been called")
	}
	if secondHandled {
		t.Error("second should not see the event as being handled (as second should not be running at all)")
	}
}

func TestEventsHaltNotHandled(t *testing.T) {
	t.Parallel()

	ab := New()
	firstCalled := false
	secondCalled := false

	firstHandled := false
	secondHandled := false

	ab.Events.Before(EventRegister, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
		firstCalled = true
		firstHandled = handled
		return false, ErrHalt
	})
	ab.Events.Before(EventRegister, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
		secondCalled = true
		secondHandled = handled
		return false, nil
	})

	handled, err := ab.Events.FireBefore(EventRegister, nil, nil)
	if err != nil {
		t.Error("Unexpected error:", err)
	}
	if handled {
		t.Error("it should not have been handled")
	}

	if !firstCalled {
		t.Error("expected first to have been called")
	}
	if firstHandled {
		t.Error("first should not see the event as being handled")
	}

	if secondCalled {
		t.Error("expected second to not have been called")
	}
	if secondHandled {
		t.Error("second should not see the event as being handled (as second should not be running at all)")
	}
}

func TestEventsErrors(t *testing.T) {
	t.Parallel()

	ab := New()
	firstCalled := false
	secondCalled := false

	expect := errors.New("error")

	ab.Events.Before(EventRegister, func(http.ResponseWriter, *http.Request, bool) (bool, error) {
		firstCalled = true
		return false, expect
	})
	ab.Events.Before(EventRegister, func(http.ResponseWriter, *http.Request, bool) (bool, error) {
		secondCalled = true
		return false, nil
	})

	_, err := ab.Events.FireBefore(EventRegister, nil, nil)
	if err != expect {
		t.Error("got the wrong error back:", err)
	}

	if !firstCalled {
		t.Error("expected first to have been called")
	}
	if secondCalled {
		t.Error("expected second to not have been called")
	}
}

func TestEventString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		ev  Event
		str string
	}{
		{EventRegister, "EventRegister"},
		{EventAuth, "EventAuth"},
		{EventOAuth2, "EventOAuth2"},
		{EventAuthFail, "EventAuthFail"},
		{EventOAuth2Fail, "EventOAuth2Fail"},
		{EventRecoverStart, "EventRecoverStart"},
		{EventRecoverEnd, "EventRecoverEnd"},
		{EventGetUser, "EventGetUser"},
		{EventGetUserSession, "EventGetUserSession"},
		{EventPasswordReset, "EventPasswordReset"},
	}

	for i, test := range tests {
		if got := test.ev.String(); got != test.str {
			t.Errorf("%d) Wrong string for Event(%d) expected: %v got: %s", i, test.ev, test.str, got)
		}
	}
}
