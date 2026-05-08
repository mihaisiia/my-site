package main

import "html/template"

type loginData struct {
	Next string
	Err  string
}

// Minimal, JS-free login page. Dark, mobile-friendly. Caddy already sets
// security headers; we set Cache-Control: no-store on the handler.
var loginTmpl = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>access</title>
<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; }
html, body { margin:0; padding:0; height:100%; }
body {
  font: 16px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  background: radial-gradient(1200px 600px at 50% -10%, #1f2733, #0b0e13);
  color: #e7ecf3;
  display: grid; place-items: center; padding: 1.5rem;
}
.card {
  width: 100%; max-width: 380px;
  background: rgba(20, 25, 33, 0.85);
  border: 1px solid rgba(255,255,255,0.06);
  border-radius: 14px; padding: 1.75rem;
  box-shadow: 0 30px 80px rgba(0,0,0,0.45);
  backdrop-filter: blur(8px);
}
h1 { margin: 0 0 0.25rem; font-size: 1.15rem; letter-spacing: 0.04em; }
p.sub { margin: 0 0 1.25rem; color: #9aa6b3; font-size: 0.92rem; }
label { display:block; font-size:0.78rem; color:#9aa6b3; margin: 0 0 0.4rem; text-transform: uppercase; letter-spacing: 0.08em; }
input[type=text] {
  width:100%; padding: 0.75rem 0.85rem; font: inherit;
  background:#0e131b; color:#e7ecf3;
  border:1px solid #2a3340; border-radius:8px;
  outline: none;
}
input[type=text]:focus { border-color:#5b8def; box-shadow: 0 0 0 3px rgba(91,141,239,0.18); }
button {
  margin-top: 1rem; width:100%; padding: 0.8rem 1rem;
  background: #5b8def; color:#0b0e13; font-weight:600;
  border: 0; border-radius: 8px; cursor:pointer;
}
button:hover { background:#7aa3ff; }
.err {
  margin: 0 0 1rem; padding: 0.6rem 0.75rem;
  background: rgba(255, 97, 97, 0.08);
  border: 1px solid rgba(255, 97, 97, 0.35);
  color: #ffb4b4; border-radius: 8px; font-size: 0.9rem;
}
footer { margin-top: 1.25rem; font-size:0.78rem; color:#5d6876; text-align:center; }
</style>
</head>
<body>
<form class="card" method="post" action="/auth/verify" autocomplete="off">
  <h1>Access</h1>
  <p class="sub">Enter your access token to continue.</p>
  {{if .Err}}<div class="err">That token isn't valid. Try again, or request a new one.</div>{{end}}
  <label for="token">Access token</label>
  <input id="token" name="token" type="text" autofocus required spellcheck="false" autocapitalize="off" autocorrect="off">
  <input type="hidden" name="next" value="{{.Next}}">
  <button type="submit">Unlock</button>
  <footer>Sessions persist on this device for 30 days.</footer>
</form>
</body>
</html>
`))
