package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"
)

const (
	defaultGateway = "http://172.19.0.5"
	defaultAcID    = "1"
	defaultDomain  = "@xyw"
	srunN          = "200"
	srunType       = "1"
	encodingName   = "srun_bx1"
	loginOS        = "Windows 10"
	loginName      = "windows"
	base64Alphabet = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
)

type Client struct {
	gateway string
	acID    string
	http    *http.Client
}

type loginState struct {
	Error    string `json:"error"`
	ErrorMsg string `json:"error_msg"`
	OnlineIP string `json:"online_ip"`
	UserName string `json:"user_name"`
}

type challengeResponse struct {
	Error     string `json:"error"`
	ErrorMsg  string `json:"error_msg"`
	Challenge string `json:"challenge"`
	ClientIP  string `json:"client_ip"`
}

type portalResponse struct {
	Error    string `json:"error"`
	ErrorMsg string `json:"error_msg"`
	OnlineIP string `json:"online_ip"`
	UserName string `json:"username"`
}

func newClient(gateway, acID string) (*Client, error) {
	parsed, err := url.Parse(gateway)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("invalid gateway URL %q", gateway)
	}
	return &Client{
		gateway: strings.TrimRight(gateway, "/"),
		acID:    acID,
		http: &http.Client{
			Timeout: 8 * time.Second,
			Transport: &http.Transport{
				Proxy: nil,
			},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *Client) getJSONP(path string, values url.Values, target any) error {
	values.Set("callback", "jsonp")
	requestURL := c.gateway + path + "?" + values.Encode()
	request, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return fmt.Errorf("create gateway request: %w", err)
	}
	request.Header.Set("User-Agent", "campus-srun/1.0")
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("contact Srun gateway: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Srun gateway returned HTTP %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read Srun response: %w", err)
	}
	start, end := bytes.IndexByte(body, '('), bytes.LastIndexByte(body, ')')
	if start < 0 || end <= start {
		return fmt.Errorf("gateway returned an invalid JSONP response")
	}
	if err := json.Unmarshal(body[start+1:end], target); err != nil {
		return fmt.Errorf("parse Srun response: %w", err)
	}
	return nil
}

func (c *Client) status() (loginState, error) {
	var state loginState
	err := c.getJSONP("/cgi-bin/rad_user_info", url.Values{}, &state)
	if err != nil {
		return state, err
	}
	if state.Error != "ok" && state.Error != "not_online_error" {
		if state.ErrorMsg != "" {
			return state, fmt.Errorf("Srun status failed: %s (%s)", state.Error, state.ErrorMsg)
		}
		return state, fmt.Errorf("Srun status failed: %s", state.Error)
	}
	if state.Error == "ok" && state.UserName == "" {
		return state, errors.New("Srun reports an online session but omitted its username")
	}
	return state, nil
}

func (c *Client) challenge(username, ip string) (challengeResponse, error) {
	values := url.Values{"username": {username}}
	if ip != "" {
		values.Set("ip", ip)
	}
	var result challengeResponse
	if err := c.getJSONP("/cgi-bin/get_challenge", values, &result); err != nil {
		return result, err
	}
	if result.Error != "" && result.Error != "ok" {
		return result, fmt.Errorf("Srun challenge failed: %s (%s)", result.Error, result.ErrorMsg)
	}
	if result.Challenge == "" {
		return result, errors.New("Srun gateway returned an empty challenge")
	}
	return result, nil
}

func (c *Client) login(username string, password []byte) (portalResponse, error) {
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()
	username = portalUsername(username)

	state, err := c.status()
	if err != nil {
		return portalResponse{}, err
	}
	if state.Error == "ok" {
		if sameUsername(state.UserName, username) {
			return portalResponse{Error: "already_online", OnlineIP: state.OnlineIP, UserName: state.UserName}, nil
		}
		return portalResponse{}, fmt.Errorf("device is already online as %q; refusing to replace that session", state.UserName)
	}

	ip := state.OnlineIP
	if net.ParseIP(ip) == nil {
		first, err := c.challenge(username, "")
		if err != nil {
			return portalResponse{}, err
		}
		ip = first.ClientIP
	}
	if net.ParseIP(ip) == nil {
		return portalResponse{}, errors.New("could not determine this server's Srun client IP")
	}

	challenge, err := c.challenge(username, ip)
	if err != nil {
		return portalResponse{}, err
	}
	if challenge.ClientIP != "" && net.ParseIP(challenge.ClientIP) != nil {
		if challenge.ClientIP != ip {
			ip = challenge.ClientIP
			challenge, err = c.challenge(username, ip)
			if err != nil {
				return portalResponse{}, err
			}
		}
	}

	passwordString := string(password)
	defer func() {
		passwordString = ""
	}()

	h := hmac.New(md5.New, []byte(challenge.Challenge))
	_, _ = h.Write([]byte(passwordString))
	hmd5 := hex.EncodeToString(h.Sum(nil))
	infoData := map[string]string{
		"username": username,
		"password": passwordString,
		"ip":       ip,
		"acid":     c.acID,
		"enc_ver":  encodingName,
	}
	plainInfo, err := json.Marshal(infoData)
	if err != nil {
		return portalResponse{}, fmt.Errorf("encode login data: %w", err)
	}
	encoded := xencode(plainInfo, []byte(challenge.Challenge))
	info := "{SRBX1}" + customBase64(encoded)
	checksumData := challenge.Challenge + strings.Join([]string{
		username, hmd5, c.acID, ip, srunN, srunType, info,
	}, challenge.Challenge)
	checksum := sha1.Sum([]byte(checksumData))

	values := url.Values{
		"action":       {"login"},
		"username":     {username},
		"password":     {"{MD5}" + hmd5},
		"chksum":       {hex.EncodeToString(checksum[:])},
		"info":         {info},
		"ac_id":        {c.acID},
		"ip":           {ip},
		"type":         {srunType},
		"n":            {srunN},
		"os":           {loginOS},
		"name":         {loginName},
		"double_stack": {"0"},
	}
	var result portalResponse
	if err := c.getJSONP("/cgi-bin/srun_portal", values, &result); err != nil {
		return result, err
	}
	if result.Error != "ok" {
		return result, portalError("login", result)
	}
	if result.UserName == "" {
		result.UserName = username
	}
	return result, nil
}

func portalUsername(username string) string {
	if strings.Contains(username, "@") {
		return username
	}
	return username + defaultDomain
}

func sameUsername(first, second string) bool {
	return portalUsername(first) == portalUsername(second)
}

func (c *Client) logout(username string) (portalResponse, error) {
	state, err := c.status()
	if err != nil {
		return portalResponse{}, err
	}
	if state.Error != "ok" || state.UserName == "" {
		return portalResponse{Error: "not_online_error", OnlineIP: state.OnlineIP}, nil
	}
	if username != "" && username != state.UserName {
		return portalResponse{}, fmt.Errorf("requested user %q does not match online account %q; refusing to log out a different account", username, state.UserName)
	}
	if net.ParseIP(state.OnlineIP) == nil {
		return portalResponse{}, errors.New("gateway did not provide a valid online IP for logout")
	}

	timestamp := fmt.Sprint(time.Now().Unix())
	const unbind = "1"
	signature := sha1.Sum([]byte(timestamp + state.UserName + state.OnlineIP + unbind + timestamp))
	values := url.Values{
		"username": {state.UserName},
		"ip":       {state.OnlineIP},
		"time":     {timestamp},
		"unbind":   {unbind},
		"sign":     {hex.EncodeToString(signature[:])},
	}
	var result portalResponse
	if err := c.getJSONP("/cgi-bin/rad_user_dm", values, &result); err != nil {
		return result, err
	}
	if result.Error != "ok" && result.Error != "logout_ok" {
		return result, portalError("logout", result)
	}
	for attempt := 0; attempt < 5; attempt++ {
		state, err = c.status()
		if err != nil {
			return result, err
		}
		if state.Error != "ok" {
			return result, nil
		}
		if attempt < 4 {
			time.Sleep(500 * time.Millisecond)
		}
	}
	return result, fmt.Errorf("Srun still reports account %q online at %s after logout", state.UserName, state.OnlineIP)
}

func portalError(action string, response portalResponse) error {
	if response.ErrorMsg != "" {
		return fmt.Errorf("Srun %s failed: %s (%s)", action, response.Error, response.ErrorMsg)
	}
	return fmt.Errorf("Srun %s failed: %s", action, response.Error)
}

func xencode(message, key []byte) []byte {
	if len(message) == 0 {
		return nil
	}
	v := make([]uint32, (len(message)+3)/4+1)
	for i, b := range message {
		v[i/4] |= uint32(b) << (uint(i%4) * 8)
	}
	v[len(v)-1] = uint32(len(message))

	k := make([]uint32, 4)
	for i, b := range key {
		if i >= 16 {
			break
		}
		k[i/4] |= uint32(b) << (uint(i%4) * 8)
	}

	n := len(v) - 1
	z, sum := v[n], uint32(0)
	rounds := 6 + 52/len(v)
	for q := 0; q < rounds; q++ {
		sum += 0x9e3779b9
		e := (sum >> 2) & 3
		for p := 0; p < n; p++ {
			y := v[p+1]
			mix := ((z >> 5) ^ (y << 2)) + ((y>>3 ^ z<<4) ^ (sum ^ y)) + (k[(p&3)^int(e)] ^ z) + v[p]
			v[p] = mix
			z = mix
		}
		y := v[0]
		mix := ((z >> 5) ^ (y << 2)) + ((y>>3 ^ z<<4) ^ (sum ^ y)) + (k[(n&3)^int(e)] ^ z) + v[n]
		v[n] = mix
		z = mix
	}

	result := make([]byte, len(v)*4)
	for i, word := range v {
		result[i*4] = byte(word)
		result[i*4+1] = byte(word >> 8)
		result[i*4+2] = byte(word >> 16)
		result[i*4+3] = byte(word >> 24)
	}
	return result
}

func customBase64(data []byte) string {
	standard := base64.StdEncoding.EncodeToString(data)
	const ordinary = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var output strings.Builder
	output.Grow(len(standard))
	for i := 0; i < len(standard); i++ {
		ch := standard[i]
		if index := strings.IndexByte(ordinary, ch); index >= 0 {
			ch = base64Alphabet[index]
		}
		output.WriteByte(ch)
	}
	return output.String()
}

func promptLine(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("open terminal: %w", err)
	}
	defer tty.Close()
	if _, err := fmt.Fprint(tty, prompt); err != nil {
		return "", fmt.Errorf("write terminal prompt: %w", err)
	}
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read terminal input: %w", err)
	}
	return strings.TrimSpace(line), nil
}

func promptPassword() ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open terminal for password prompt: %w", err)
	}
	defer tty.Close()

	fd := tty.Fd()
	var original syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&original)))
	if errno != 0 {
		return nil, fmt.Errorf("read terminal settings: %w", errno)
	}
	hidden := original
	hidden.Lflag &^= syscall.ECHO | syscall.ICANON
	hidden.Cc[syscall.VMIN] = 1
	hidden.Cc[syscall.VTIME] = 0
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&hidden)))
	if errno != 0 {
		return nil, fmt.Errorf("configure terminal for masked password input: %w", errno)
	}
	defer syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&original)))

	if _, err := fmt.Fprint(tty, "Campus password: "); err != nil {
		return nil, fmt.Errorf("write password prompt: %w", err)
	}
	password, err := readMaskedPassword(tty, tty)
	_, _ = fmt.Fprintln(tty)
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	return password, nil
}

func readMaskedPassword(reader io.Reader, writer io.Writer) ([]byte, error) {
	var password []byte
	displayedBytes := 0
	var input [1]byte

	for {
		n, err := reader.Read(input[:])
		if n == 0 {
			if err != nil {
				return password, err
			}
			continue
		}

		switch input[0] {
		case '\r', '\n':
			return password, nil
		case 8, 127:
			if len(password) == 0 {
				continue
			}
			removeBytes := 1
			if displayedBytes == len(password) {
				_, runeBytes := utf8.DecodeLastRune(password)
				displayedBytes = len(password) - runeBytes
				removeBytes = runeBytes
				if _, err := io.WriteString(writer, "\b \b"); err != nil {
					return password, fmt.Errorf("update password mask: %w", err)
				}
			}
			password = password[:len(password)-removeBytes]
		case 21:
			for displayedBytes > 0 {
				if _, err := io.WriteString(writer, "\b \b"); err != nil {
					return password, fmt.Errorf("clear password mask: %w", err)
				}
				_, size := utf8.DecodeLastRune(password[:displayedBytes])
				displayedBytes -= size
			}
			for i := range password {
				password[i] = 0
			}
			password = password[:0]
		default:
			password = append(password, input[0])
			for displayedBytes < len(password) && utf8.FullRune(password[displayedBytes:]) {
				_, size := utf8.DecodeRune(password[displayedBytes:])
				displayedBytes += size
				if _, err := io.WriteString(writer, "*"); err != nil {
					return password, fmt.Errorf("write password mask: %w", err)
				}
			}
		}

		if err != nil {
			return password, err
		}
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "campus-srun: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printUsage()
		return nil
	}
	action := args[0]
	options := flag.NewFlagSet(action, flag.ContinueOnError)
	options.SetOutput(io.Discard)
	gateway := options.String("gateway", defaultGateway, "Srun gateway URL")
	acID := options.String("ac-id", defaultAcID, "Srun access point ID")
	username := options.String("username", "", "campus username")
	if err := options.Parse(args[1:]); err != nil {
		printUsage()
		return err
	}
	if options.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(options.Args(), " "))
	}
	client, err := newClient(*gateway, *acID)
	if err != nil {
		return err
	}

	switch action {
	case "status":
		state, err := client.status()
		if err != nil {
			return err
		}
		if state.Error == "ok" && state.UserName != "" {
			fmt.Printf("%s (%s) is online\n", state.UserName, state.OnlineIP)
		} else {
			fmt.Printf("%s is offline\n", state.OnlineIP)
		}
		return nil
	case "logout":
		result, err := client.logout(*username)
		if err != nil {
			return err
		}
		if result.Error == "not_online_error" {
			fmt.Printf("%s is already offline\n", result.OnlineIP)
		} else {
			fmt.Printf("%s logged out\n", result.OnlineIP)
		}
		return nil
	case "login":
		user := *username
		if user == "" {
			user, err = promptLine("Campus username: ")
			if err != nil {
				return err
			}
		}
		if strings.TrimSpace(user) == "" {
			return errors.New("username is required")
		}
		state, err := client.status()
		if err != nil {
			return err
		}
		if state.Error == "ok" {
			if sameUsername(state.UserName, user) {
				fmt.Printf("%s (%s) is already online\n", state.UserName, state.OnlineIP)
				return nil
			}
			return fmt.Errorf("device is already online as %q; refusing to replace that session", state.UserName)
		}
		password, err := promptPassword()
		if err != nil {
			return err
		}
		if len(password) == 0 {
			return errors.New("password is required")
		}
		result, err := client.login(user, password)
		if err != nil {
			return err
		}
		if result.Error == "already_online" {
			fmt.Printf("%s (%s) is already online\n", result.UserName, result.OnlineIP)
		} else {
			fmt.Printf("%s (%s) logged in\n", result.UserName, result.OnlineIP)
		}
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown command %q", action)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  campus-srun status
  campus-srun login [-username USER]
  campus-srun logout [-username USER]

Login prompts for the password with one * displayed per typed character; the
password itself is never echoed, accepted as a command-line option, or written
to a config file.
Logout uses the currently authenticated account and needs no password.

Common options for each command:
  -gateway URL   Srun gateway (default http://172.19.0.5)
  -ac-id ID      Srun access point (default 1)`)
}
