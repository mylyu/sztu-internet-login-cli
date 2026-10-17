package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestXencodeIsDeterministicAndWordAligned(t *testing.T) {
	message := []byte(`{"username":"test","password":"secret","acid":"1","ip":"10.0.0.2","enc_ver":"srun_bx1"}`)
	key := []byte("0123456789abcdef0123456789abcdef")
	first := xencode(message, key)
	second := xencode(message, key)
	if len(first) == 0 || len(first)%4 != 0 {
		t.Fatalf("xencode returned invalid byte length %d", len(first))
	}
	if string(first) != string(second) {
		t.Fatal("xencode output is not deterministic")
	}
	encoded := customBase64(first)
	for _, char := range encoded {
		if char != '=' && !strings.ContainsRune(base64Alphabet, char) {
			t.Fatalf("custom base64 contains unexpected character %q", char)
		}
	}
}

func TestLoginBuildsSrunRequestWithoutPlaintextPassword(t *testing.T) {
	const username = "test-user@xyw"
	const password = "test-secret-not-for-url"
	const clientIP = "10.10.20.30"
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cgi-bin/rad_user_info":
			fmt.Fprint(w, `jsonp({"error":"not_online_error","online_ip":"`+clientIP+`"})`)
		case "/cgi-bin/get_challenge":
			if r.URL.Query().Get("username") != username || r.URL.Query().Get("ip") != clientIP {
				t.Errorf("unexpected challenge parameters: %v", r.URL.Query())
			}
			fmt.Fprint(w, `jsonp({"error":"ok","challenge":"`+token+`","client_ip":"`+clientIP+`"})`)
		case "/cgi-bin/srun_portal":
			query := r.URL.Query()
			if query.Get("action") != "login" || query.Get("username") != username {
				t.Errorf("unexpected login parameters: %v", query)
			}
			if query.Get("password") == "" || query.Get("password") == password {
				t.Error("login password parameter is missing or plaintext")
			}
			expectedHMAC := hmac.New(md5.New, []byte(token))
			_, _ = expectedHMAC.Write([]byte(password))
			expectedHMD5 := hex.EncodeToString(expectedHMAC.Sum(nil))
			if query.Get("password") != "{MD5}"+expectedHMD5 {
				t.Error("login password parameter does not contain the expected HMAC-MD5")
			}
			if query.Get("os") != loginOS || query.Get("name") != loginName || query.Get("double_stack") != "0" {
				t.Error("login request is missing the portal's client metadata")
			}
			checksumData := token + strings.Join([]string{
				username, expectedHMD5, "1", clientIP, srunN, srunType, query.Get("info"),
			}, token)
			expectedChecksum := sha1.Sum([]byte(checksumData))
			if query.Get("chksum") != hex.EncodeToString(expectedChecksum[:]) {
				t.Error("login request has an invalid Srun SHA-1 checksum")
			}
			if strings.Contains(r.URL.RawQuery, password) {
				t.Error("plaintext password leaked into request URL")
			}
			if !strings.HasPrefix(query.Get("info"), "{SRBX1}") || len(query.Get("chksum")) != 40 {
				t.Error("login request is missing encoded payload or SHA-1 checksum")
			}
			fmt.Fprint(w, `jsonp({"error":"ok","username":"`+username+`","online_ip":"`+clientIP+`"})`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := newClient(server.URL, "1")
	if err != nil {
		t.Fatal(err)
	}
	passwordBytes := []byte(password)
	result, err := client.login(username, passwordBytes)
	if err != nil {
		t.Fatal(err)
	}
	if result.Error != "ok" || result.UserName != username {
		t.Fatalf("unexpected login result: %+v", result)
	}
	for _, value := range passwordBytes {
		if value != 0 {
			t.Fatal("login did not clear the caller's password buffer")
		}
	}
}

func TestLoginAlreadyOnlineDoesNotRequestPasswordAndClearsBuffer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cgi-bin/rad_user_info" {
			t.Errorf("unexpected request while already online: %s", r.URL.Path)
		}
		fmt.Fprint(w, `jsonp({"error":"ok","user_name":"test-user","online_ip":"10.10.20.30"})`)
	}))
	defer server.Close()
	client, err := newClient(server.URL, "1")
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("not-used")
	result, err := client.login("test-user@xyw", password)
	if err != nil {
		t.Fatal(err)
	}
	if result.Error != "already_online" {
		t.Fatalf("unexpected result: %+v", result)
	}
	for _, value := range password {
		if value != 0 {
			t.Fatal("already-online path did not clear the password buffer")
		}
	}
}

func TestPortalUsernameAddsSiteDomainOnce(t *testing.T) {
	if got := portalUsername("00817"); got != "00817@xyw" {
		t.Fatalf("portalUsername() = %q, want 00817@xyw", got)
	}
	if got := portalUsername("00817@xyw"); got != "00817@xyw" {
		t.Fatalf("portalUsername() duplicated domain: %q", got)
	}
	if !sameUsername("00817", "00817@xyw") {
		t.Fatal("sameUsername() did not recognize equivalent portal usernames")
	}
}

func TestReadMaskedPasswordShowsStarsAndHandlesBackspace(t *testing.T) {
	var maskedOutput strings.Builder
	password, err := readMaskedPassword(strings.NewReader("abc\x7fd\n"), &maskedOutput)
	if err != nil {
		t.Fatal(err)
	}
	if string(password) != "abd" {
		t.Fatalf("readMaskedPassword() = %q, want %q", password, "abd")
	}
	if got, want := maskedOutput.String(), "***\b \b*"; got != want {
		t.Fatalf("masked output = %q, want %q", got, want)
	}
	if strings.Contains(maskedOutput.String(), "abc") {
		t.Fatal("password text was written to the terminal")
	}
}

func TestReadMaskedPasswordMasksUnicodeByRuneAndHandlesLineClear(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		password string
		masked   string
	}{
		{name: "unicode", input: "é\n", password: "é", masked: "*"},
		{name: "unicode backspace", input: "é\x7fX\n", password: "X", masked: "*\b \b*"},
		{name: "clear line", input: "old\x15new\n", password: "new", masked: "***" + strings.Repeat("\b \b", 3) + "***"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var maskedOutput strings.Builder
			password, err := readMaskedPassword(strings.NewReader(test.input), &maskedOutput)
			if err != nil {
				t.Fatal(err)
			}
			if string(password) != test.password {
				t.Fatalf("readMaskedPassword() = %q, want %q", password, test.password)
			}
			if maskedOutput.String() != test.masked {
				t.Fatalf("masked output = %q, want %q", maskedOutput.String(), test.masked)
			}
			if strings.Contains(maskedOutput.String(), test.password) {
				t.Fatal("password text was written to the terminal")
			}
		})
	}
}

func TestLogoutUsesCurrentAccountAndDoesNotRequirePassword(t *testing.T) {
	const clientIP = "10.10.20.30"
	var logoutQuery url.Values
	var mu sync.Mutex
	logoutRequested := false
	staleStatuses := 1
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/cgi-bin/rad_user_info":
			if !logoutRequested || staleStatuses > 0 {
				if logoutRequested {
					staleStatuses--
				}
				fmt.Fprint(w, `jsonp({"error":"ok","user_name":"test-user","online_ip":"`+clientIP+`"})`)
			} else {
				fmt.Fprint(w, `jsonp({"error":"not_online_error","online_ip":"`+clientIP+`"})`)
			}
		case "/cgi-bin/rad_user_dm":
			logoutQuery = r.URL.Query()
			logoutRequested = true
			fmt.Fprint(w, `jsonp({"error":"ok","online_ip":"`+clientIP+`"})`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := newClient(server.URL, "1")
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.logout("")
	if err != nil {
		t.Fatal(err)
	}
	if result.Error != "ok" {
		t.Fatalf("unexpected logout result: %+v", result)
	}
	timestamp := logoutQuery.Get("time")
	if _, err := strconv.ParseInt(timestamp, 10, 64); err != nil {
		t.Fatalf("logout timestamp is invalid: %q", timestamp)
	}
	signature := sha1.Sum([]byte(timestamp + "test-user" + clientIP + "1" + timestamp))
	if logoutQuery.Get("callback") != "jsonp" ||
		logoutQuery.Get("username") != "test-user" ||
		logoutQuery.Get("ip") != clientIP ||
		logoutQuery.Get("unbind") != "1" ||
		logoutQuery.Get("sign") != hex.EncodeToString(signature[:]) ||
		logoutQuery.Has("password") ||
		logoutQuery.Has("action") {
		t.Fatalf("unexpected logout parameters: %v", logoutQuery)
	}
}

func TestDecodeJSONP(t *testing.T) {
	var state loginState
	client := &Client{
		gateway: "http://test.invalid",
		http: &http.Client{
			Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				body := `jsonp({"error":"ok","online_ip":"10.0.0.2","user_name":"test"})`
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(body)),
					Request:    request,
				}, nil
			}),
		},
	}

	if err := client.getJSONP("/cgi-bin/rad_user_info", url.Values{}, &state); err != nil {
		t.Fatal(err)
	}
	if state.Error != "ok" || state.UserName != "test" {
		t.Fatalf("unexpected decoded status: %+v", state)
	}
}

func TestLogoutRefusesAnotherAccount(t *testing.T) {
	requestedLogout := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cgi-bin/rad_user_info" {
			fmt.Fprint(w, `jsonp({"error":"ok","user_name":"actual-user","online_ip":"10.10.20.30"})`)
			return
		}
		requestedLogout = true
	}))
	defer server.Close()
	client, err := newClient(server.URL, "1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.logout("different-user"); err == nil {
		t.Fatal("expected a mismatch error")
	}
	if requestedLogout {
		t.Fatal("sent logout request for a different account")
	}
}

func TestGatewayRedirectIsNotFollowed(t *testing.T) {
	redirectTargetHit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectTargetHit = true
	}))
	defer target.Close()
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer gateway.Close()

	client, err := newClient(gateway.URL, "1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.status(); err == nil {
		t.Fatal("expected redirect response to fail")
	}
	if redirectTargetHit {
		t.Fatal("followed a gateway redirect")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
