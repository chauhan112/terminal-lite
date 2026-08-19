package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

//go:embed public
var embedded embed.FS

const (
	sessionCookieName = "terminal_session"
	sessionTTL        = 30 * 24 * time.Hour
	idleTimeout       = 5 * time.Minute
)

var (
	token         string
	loginUser     string
	loginPass     string
	sessionSecret []byte
	shell         string
	workdir       string
	upgrader      = websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true
			}
			u, err := url.Parse(origin)
			if err != nil {
				return false
			}
			return strings.EqualFold(u.Hostname(), hostOnly(r.Host))
		},
	}
)

type clientMessage struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

func hostOnly(hostport string) string {
	host := hostport
	if i := strings.LastIndex(hostport, ":"); i != -1 {
		host = hostport[:i]
	}
	return strings.Trim(host, "[]")
}

func deriveSessionSecret() []byte {
	switch {
	case os.Getenv("SESSION_SECRET") != "":
		return hashSecret(os.Getenv("SESSION_SECRET"))
	case token != "":
		return hashSecret(token)
	default:
		return hashSecret(loginUser + ":" + loginPass)
	}
}

func hashSecret(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func issueSession(user string) string {
	expHex := strconv.FormatInt(time.Now().Add(sessionTTL).Unix(), 16)
	payload := user + "." + expHex
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte(payload))
	return payload + "." + hex.EncodeToString(mac.Sum(nil))
}

func validSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 {
		return false
	}
	user, expHex, sig := parts[0], parts[1], parts[2]
	exp, err := strconv.ParseInt(expHex, 16, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(user), []byte(loginUser)) != 1 {
		return false
	}
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte(user + "." + expHex))
	got, err := hex.DecodeString(sig)
	if err != nil || !hmac.Equal(got, mac.Sum(nil)) {
		return false
	}
	return true
}

func authenticated(r *http.Request) bool {
	if loginUser != "" && validSession(r) {
		return true
	}
	if token != "" {
		t := r.URL.Query().Get("token")
		if subtle.ConstantTimeCompare([]byte(t), []byte(token)) == 1 {
			return true
		}
	}
	return false
}

func requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (loginUser != "" || token != "") && !authenticated(r) {
			if r.URL.Path == "/ws" || loginUser == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func serveLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if loginUser == "" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		data, err := embedded.ReadFile("public/login.html")
		if err != nil {
			http.Error(w, "login unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	case http.MethodPost:
		if loginUser == "" {
			http.Error(w, "login disabled", http.StatusNotFound)
			return
		}
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		userOK := subtle.ConstantTimeCompare([]byte(creds.Username), []byte(loginUser)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(creds.Password), []byte(loginPass)) == 1
		if !userOK || !passOK {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials"})
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    issueSession(loginUser),
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(sessionTTL.Seconds()),
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func serveLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

// A session ties a PTY shell to a replay buffer so it survives WebSocket
// disconnects (page refresh) and can be reattached. It is killed by the idle
// timeout or an explicit "kill" message (tab close).
const replayLimit = 128 * 1024

var (
	sessionsMu sync.Mutex
	sessions   = map[string]*session{}
)

type session struct {
	id    string
	ptmx  *os.File
	cmd   *exec.Cmd
	mu    sync.Mutex
	out   []byte
	conn  *websocket.Conn
	idle  *time.Timer
	once  sync.Once
}

func randomID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newSession() *session {
	cmd := exec.Command(shell, shellArgs...)
	cmd.Dir = workdir
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		log.Println("pty:", err)
		return nil
	}
	s := &session{id: randomID(), ptmx: ptmx, cmd: cmd}
	s.idle = time.AfterFunc(idleTimeout, s.expire)
	sessionsMu.Lock()
	sessions[s.id] = s
	sessionsMu.Unlock()
	return s
}

func (s *session) appendOut(b []byte) {
	s.out = append(s.out, b...)
	if len(s.out) > replayLimit {
		n := copy(s.out, s.out[len(s.out)-replayLimit:])
		s.out = s.out[:n]
	}
}

func (s *session) expire() {
	s.once.Do(func() {
		sessionsMu.Lock()
		delete(sessions, s.id)
		sessionsMu.Unlock()
		s.idle.Stop()
		if s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
		}
		_ = s.ptmx.Close()
		_ = s.cmd.Wait()
		s.mu.Lock()
		c := s.conn
		s.conn = nil
		s.mu.Unlock()
		if c != nil {
			_ = c.Close()
		}
	})
}

// pump reads the PTY forever: buffers output and forwards it to the attached
// connection, if any. Runs even while detached so long jobs keep the session
// alive and their output is buffered for replay.
func (s *session) pump() {
	buf := make([]byte, 32*1024)
	for {
		n, err := s.ptmx.Read(buf)
		if n > 0 {
			s.mu.Lock()
			s.appendOut(buf[:n])
			s.idle.Reset(idleTimeout)
			if s.conn != nil {
				_ = s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if s.conn.WriteMessage(websocket.BinaryMessage, buf[:n]) != nil {
					s.conn = nil
				}
			}
			s.mu.Unlock()
		}
		if err != nil {
			s.expire()
			return
		}
	}
}

func serveWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade:", err)
		return
	}

	var s *session
	if id := r.URL.Query().Get("session"); id != "" {
		sessionsMu.Lock()
		s = sessions[id]
		sessionsMu.Unlock()
	}
	if s == nil {
		s = newSession()
		if s == nil {
			conn.Close()
			return
		}
		go s.pump()
	}

	// Attach: replay buffered output, then announce the session id.
	s.mu.Lock()
	if s.conn != nil {
		old := s.conn
		s.conn = nil
		_ = old.Close()
	}
	s.conn = conn
	s.idle.Reset(idleTimeout)
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if len(s.out) > 0 {
		_ = conn.WriteMessage(websocket.BinaryMessage, s.out)
	}
	_ = conn.WriteMessage(websocket.TextMessage,
		[]byte(`{"type":"session","id":"`+s.id+`"}`))
	s.mu.Unlock()

	conn.SetReadLimit(1 << 20)
	_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	})

	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTicker(25 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				s.mu.Lock()
				if s.conn == conn {
					_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
					if conn.WriteMessage(websocket.PingMessage, nil) != nil {
						s.conn = nil
					}
				}
				s.mu.Unlock()
			case <-done:
				return
			}
		}
	}()

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			break
		}
		s.mu.Lock()
		s.idle.Reset(idleTimeout)
		s.mu.Unlock()
		var msg clientMessage
		if json.Unmarshal(raw, &msg) != nil {
			continue
		}
		switch msg.Type {
		case "input":
			if msg.Data != "" {
				_, _ = s.ptmx.Write([]byte(msg.Data))
			}
		case "resize":
			if msg.Cols > 0 && msg.Rows > 0 {
				_ = pty.Setsize(s.ptmx, &pty.Winsize{
					Cols: uint16(msg.Cols),
					Rows: uint16(msg.Rows),
				})
			}
		case "kill":
			s.expire()
		}
	}

	// Detach: keep the session running for reattach (refresh) unless killed.
	s.mu.Lock()
	if s.conn == conn {
		s.conn = nil
	}
	s.mu.Unlock()
	conn.Close()
}

var shellArgs []string

func bashRcfile() []string {
	if filepath.Base(shell) != "bash" {
		return nil
	}
	rc := filepath.Join(os.TempDir(), "terminal-lite-"+strconv.Itoa(os.Getuid())+".bashrc")
	content := "[ -r /etc/bash.bashrc ] && . /etc/bash.bashrc\n" +
		"[ -r \"$HOME/.bashrc\" ] && . \"$HOME/.bashrc\"\n" +
		"PS1='\\[\\033[1;32m\\]\\u@\\h\\[\\033[0m\\]:\\[\\033[1;34m\\]\\w\\[\\033[0m\\]\\n\\$ '\n"
	if err := os.WriteFile(rc, []byte(content), 0o600); err != nil {
		log.Println("rcfile:", err)
		return nil
	}
	return []string{"--rcfile", rc}
}

func authMode() string {
	switch {
	case loginUser != "" && token != "":
		return "login+token"
	case loginUser != "":
		return "login"
	case token != "":
		return "token"
	default:
		return "none"
	}
}

func main() {
	defaultShell := os.Getenv("SHELL")
	if defaultShell == "" {
		defaultShell = "/bin/bash"
	}
	if _, err := os.Stat(defaultShell); err != nil {
		defaultShell = "/bin/sh"
	}

	addr := flag.String("addr", "", "listen address (env PORT or :8080)")
	flag.StringVar(&shell, "shell", defaultShell, "shell to spawn")
	flag.StringVar(&token, "token", os.Getenv("TOKEN"), "auth token (env TOKEN)")
	flag.StringVar(&loginUser, "login-user", os.Getenv("LOGIN_USER"), "login username (env LOGIN_USER)")
	flag.StringVar(&loginPass, "login-pass", os.Getenv("LOGIN_PASS"), "login password (env LOGIN_PASS)")
	flag.StringVar(&workdir, "workdir", os.Getenv("WORKDIR"), "initial working directory for shells (env WORKDIR)")
	flag.Parse()

	if workdir == "" {
		workdir, _ = os.UserHomeDir()
	}
	if fi, err := os.Stat(workdir); err != nil || !fi.IsDir() {
		log.Fatalf("workdir %q is not a directory", workdir)
	}

	if (loginUser == "") != (loginPass == "") {
		log.Fatal("LOGIN_USER and LOGIN_PASS must be set together")
	}
	sessionSecret = deriveSessionSecret()

	// Two-line prompt (user@host, then $) for bash sessions. Via --rcfile so
	// it wins over ~/.bashrc, which would otherwise reset PS1.
	shellArgs = bashRcfile()

	if *addr == "" {
		if p := os.Getenv("PORT"); p != "" {
			*addr = ":" + p
		} else {
			*addr = ":8080"
		}
	}

	sub, err := fs.Sub(embedded, "public")
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", serveLogin)
	mux.HandleFunc("/logout", serveLogout)
	mux.Handle("/ws", requireAuth(http.HandlerFunc(serveWS)))
	mux.Handle("/", requireAuth(http.FileServer(http.FS(sub))))

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("terminal listening on http://0.0.0.0%s (shell: %s, auth: %s)", *addr, shell, authMode())
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
