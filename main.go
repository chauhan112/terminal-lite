package main

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

//go:embed public
var embedded embed.FS

var (
	token  string
	shell  string
	upgrader = websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
)

type clientMessage struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

func requireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" {
			t := r.URL.Query().Get("token")
			if subtle.ConstantTimeCompare([]byte(t), []byte(token)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func serveWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade:", err)
		return
	}
	defer conn.Close()

	cmd := exec.Command(shell)
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
	flag.Parse()

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
	mux.Handle("/ws", requireToken(http.HandlerFunc(serveWS)))
	mux.Handle("/", http.FileServer(http.FS(sub)))

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("terminal listening on http://0.0.0.0%s (shell: %s, auth: %v)", *addr, shell, token != "")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
