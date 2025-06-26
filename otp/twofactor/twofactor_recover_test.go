package twofactor

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/aarondl/authboss/v3"
	"github.com/aarondl/authboss/v3/mocks"
)

func TestSetup(t *testing.T) {
	t.Parallel()

	router := &mocks.Router{}
	renderer := &mocks.Renderer{}

	ab := &authboss.Authboss{}
	ab.Config.Core.Router = router
	ab.Config.Core.ViewRenderer = renderer
	ab.Config.Core.ErrorHandler = &mocks.ErrorHandler{}

	recovery := &Recovery{Authboss: ab}
	if err := recovery.Setup(); err != nil {
		t.Error(err)
	}

	if err := router.HasGets("/2fa/recovery/regen"); err != nil {
		t.Error(err)
	}
	if err := router.HasPosts("/2fa/recovery/regen"); err != nil {
		t.Error(err)
	}

	if err := renderer.HasLoadedViews(PageRecovery2FA); err != nil {
		t.Error(err)
	}
}

type testHarness struct {
	recovery *Recovery
	ab       *authboss.Authboss

	bodyReader *mocks.BodyReader
	responder  *mocks.Responder
	redirector *mocks.Redirector
	session    *mocks.ClientStateRW
	storer     *mocks.ServerStorer
}

func testSetup() *testHarness {
	harness := &testHarness{}

	harness.ab = authboss.New()
	harness.bodyReader = &mocks.BodyReader{}
	harness.redirector = &mocks.Redirector{}
	harness.responder = &mocks.Responder{}
	harness.session = mocks.NewClientRW()
	harness.storer = mocks.NewServerStorer()

	harness.ab.Config.Core.BodyReader = harness.bodyReader
	harness.ab.Config.Core.Logger = mocks.Logger{}
	harness.ab.Config.Core.Responder = harness.responder
	harness.ab.Config.Core.Redirector = harness.redirector
	harness.ab.Config.Storage.SessionState = harness.session
	harness.ab.Config.Storage.Server = harness.storer

	harness.recovery = &Recovery{harness.ab}

	return harness
}

func TestGetRegen(t *testing.T) {
	t.Parallel()

	var err error
	harness := testSetup()
	user := &mocks.User{Email: "test@test.com", RecoveryCodes: "a,b"}
	harness.storer.Users["test@test.com"] = user

	rec := httptest.NewRecorder()
	r := mocks.Request("GET")
	w := harness.ab.NewResponse(rec)

	harness.session.ClientValues[authboss.SessionKey] = "test@test.com"
	r, err = harness.ab.LoadClientState(w, r)
	if err != nil {
		t.Error(err)
	}

	if err := harness.recovery.GetRegen(w, r); err != nil {
		t.Error(err)
	}

	if harness.responder.Data[DataNumRecoveryCodes].(int) != 2 {
		t.Error("want two recovery codes")
	}
}

func TestPostRegen(t *testing.T) {
	t.Parallel()

	var err error
	harness := testSetup()
	user := &mocks.User{Email: "test@test.com", RecoveryCodes: "a,b"}
	harness.storer.Users["test@test.com"] = user

	rec := httptest.NewRecorder()
	r := mocks.Request("POST")
	w := harness.ab.NewResponse(rec)

	harness.session.ClientValues[authboss.SessionKey] = "test@test.com"
	r, err = harness.ab.LoadClientState(w, r)
	if err != nil {
		t.Error(err)
	}

	if err := harness.recovery.PostRegen(w, r); err != nil {
		t.Error(err)
	}

	userStrs := DecodeRecoveryCodes(user.GetRecoveryCodes())
	dataStrs := harness.responder.Data[DataRecoveryCodes].([]string)

	if ulen, dlen := len(userStrs), len(dataStrs); ulen != dlen {
		t.Errorf("userStrs: %d dataStrs: %d", ulen, dlen)
	}

	for i := range userStrs {
		err := bcrypt.CompareHashAndPassword([]byte(userStrs[i]), []byte(dataStrs[i]))
		if err != nil {
			t.Error("password mismatch:", userStrs[i], dataStrs[i])
		}
	}
}

func TestGenerateRecoveryCodes(t *testing.T) {
	t.Parallel()

	codes, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}

	if len(codes) != 10 {
		t.Error("it should create 10 codes, got:", len(codes))
	}

	rgx := regexp.MustCompile(`^[0-9a-z]{5}-[0-9a-z]{5}$`)
	for _, c := range codes {
		if !rgx.MatchString(c) {
			t.Errorf("code %s did not match regexp", c)
		}
	}
}

func TestHashRecoveryCodes(t *testing.T) {
	t.Parallel()

	codes, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}

	if len(codes) != 10 {
		t.Error("it should create 10 codes, got:", len(codes))
	}

	cryptedCodes, err := BCryptRecoveryCodes(codes)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range cryptedCodes {
		if !strings.HasPrefix(c, "$2a$10$") {
			t.Error("code did not look like bcrypt:", c)
		}
	}
}

func TestUseRecoveryCode(t *testing.T) {
	t.Parallel()

	codes, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}

	if len(codes) != 10 {
		t.Error("it should create 10 codes, got:", len(codes))
	}

	cryptedCodes, err := BCryptRecoveryCodes(codes)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range cryptedCodes {
		if !strings.HasPrefix(c, "$2a$10$") {
			t.Error("code did not look like bcrypt:", c)
		}
	}

	remaining, ok := UseRecoveryCode(cryptedCodes, codes[4])
	if !ok {
		t.Error("should have used a code")
	}

	if want, got := len(cryptedCodes)-1, len(remaining); want != got {
		t.Error("want:", want, "got:", got)
	}

	if cryptedCodes[4] == remaining[4] {
		t.Error("it should have used number 4")
	}

	remaining, ok = UseRecoveryCode(remaining, codes[0])
	if !ok {
		t.Error("should have used a code")
	}

	if want, got := len(cryptedCodes)-2, len(remaining); want != got {
		t.Error("want:", want, "got:", got)
	}

	if cryptedCodes[0] == remaining[0] {
		t.Error("it should have used number 0")
	}

	remaining, ok = UseRecoveryCode(remaining, codes[len(codes)-1])
	if !ok {
		t.Error("should have used a code")
	}

	if want, got := len(cryptedCodes)-3, len(remaining); want != got {
		t.Error("want:", want, "got:", got)
	}

	if cryptedCodes[len(cryptedCodes)-1] == remaining[len(remaining)-1] {
		t.Error("it should have used number 0")
	}
}
