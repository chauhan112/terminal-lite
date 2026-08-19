# terminal

Web terminal (xterm.js + PTY over WebSocket) with login session + token auth.

## Config

Copy `.env.sample` to `.env`:

| Var | Description |
|---|---|
| `TOKEN` | Bearer-style token for `?token=` URL auth |
| `PORT` | Listen port (default 8080) |
| `LOGIN_USER` / `LOGIN_PASS` | Web login credentials (username + password) |
| `WORKDIR` | Initial working directory for new shells |
| `SESSION_SECRET` | Optional cookie-signing secret (defaults to sha256 of TOKEN) |

Login sets an HttpOnly cookie valid for 30 days.

## Rebuild + restart (one-liner)

```bash
cd /home/raja/timeline/2026/q3/terminal && go build -o terminal . && sudo cp app-terminal.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl restart app-terminal && systemctl --no-pager status app-terminal | head -5
```

## Logs

```bash
journalctl -u app-terminal -f
```
