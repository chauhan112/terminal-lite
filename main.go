package main

import (
	"crypto/hmac"
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
	"strconv"
	"strings"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

//go:embed public
var embedded embed.FS

const (
	sessionCookieName = "terminal_session"
	sessionTTL        = 30 * 24 * time.Hour
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

func serveWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade:", err)
		return
	}
	defer conn.Close()

	cmd := exec.Command(shell)
	cmd.Dir = workdir
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		log.Println("pty:", err)
		return
	}
	defer func() {
		ptmx.Close()
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		cmd.Wait()
	}()

	conn.SetReadLimit(1 << 20)
	_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 32*1024)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if conn.WriteMessage(websocket.BinaryMessage, buf[:n]) != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	go func() {
		t := time.NewTicker(25 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if conn.WriteMessage(websocket.PingMessage, nil) != nil {
					return
				}
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
		var msg clientMessage
		if json.Unmarshal(raw, &msg) != nil {
			continue
		}
		switch msg.Type {
		case "input":
			if msg.Data != "" {
				_, _ = ptmx.Write([]byte(msg.Data))
			}
		case "resize":
			if msg.Cols > 0 && msg.Rows > 0 {
				_ = pty.Setsize(ptmx, &pty.Winsize{
					Cols: uint16(msg.Cols),
					Rows: uint16(msg.Rows),
				})
			}
		}
		if err != nil {
			break
		}
	}
	conn.Close()
	<-done
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
