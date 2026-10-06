package main

import (
	"database/sql"
	"embed"
	"fmt"
	"html"
	"io/fs"
	"net/http"
	"strings"

	"fence/pkg/clientip"
	"fence/pkg/routing"
)

//go:embed brand/splash.jpg brand/blocked.jpg brand/error.jpg
var brandArt embed.FS

const fessAuthor = "Роман Сергеевич Кислов"
const fessAuthorEN = "Roman Sergeyevich Kislov"

type fessPageKind string

const (
	pageSplash     fessPageKind = "splash"
	pageBlocked    fessPageKind = "blocked"
	pageError      fessPageKind = "error"
	pageChallenge  fessPageKind = "challenge"
)

func brandArtPath(kind fessPageKind) string {
	switch kind {
	case pageSplash:
		return "/_fess/art/splash.jpg"
	case pageBlocked:
		return "/_fess/art/blocked.jpg"
	default:
		return "/_fess/art/error.jpg"
	}
}

func serveBrandAsset(w http.ResponseWriter, r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	p := r.URL.Path
	var file string
	switch p {
	case "/_fess/art/splash.jpg":
		file = "brand/splash.jpg"
	case "/_fess/art/blocked.jpg":
		file = "brand/blocked.jpg"
	case "/_fess/art/error.jpg":
		file = "brand/error.jpg"
	default:
		return false
	}
	b, err := fs.ReadFile(brandArt, file)
	if err != nil {
		http.NotFound(w, r)
		return true
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
	return true
}

func writeFESSSplash(w http.ResponseWriter) {
	writeFESSPage(w, http.StatusOK, pageSplash, "FESS", "Frontend Security Server",
		"Шлюз работает. Настройте сайт в панели управления, чтобы трафик пошёл на ваш бэкенд.", "")
}

func writeFESSError(w http.ResponseWriter, status int, kind fessPageKind, title, lead string) {
	writeFESSPage(w, status, kind, title, lead, "", "")
}

func writeFESSChallenge(w http.ResponseWriter, verifyURL string) {
	writeFESSPage(w, http.StatusForbidden, pageChallenge, "Проверка браузера",
		"FESS хочет убедиться, что запрос идёт от человека.",
		"Если страница не открылась сама, нажмите «Продолжить».", verifyURL)
}

func brandArtFit(kind fessPageKind) string {
	if kind == pageBlocked {
		return "85% 42% / cover"
	}
	return "center / cover"
}

func writeFESSPage(w http.ResponseWriter, status int, kind fessPageKind, title, lead, extra, actionURL string) {
	title = html.EscapeString(title)
	lead = html.EscapeString(lead)
	extra = html.EscapeString(extra)
	art := html.EscapeString(brandArtPath(kind))
	code := status
	if code <= 0 {
		code = http.StatusOK
	}
	btn := ""
	if strings.TrimSpace(actionURL) != "" {
		href := html.EscapeString(actionURL)
		btn = fmt.Sprintf(`<p class="cta"><a href="%s">Продолжить</a></p>
<script>location.replace(%q);</script>`, href, actionURL)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s · FESS</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  html, body { margin: 0; min-height: 100%%; }
  body {
    font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
    color: #f4f1ea;
    background: #0b0b0c url("%s") %s no-repeat fixed;
  }
  .veil {
    min-height: 100vh;
    background: linear-gradient(180deg, rgba(8,8,9,.28) 0%%, rgba(8,8,9,.78) 72%%, #080809 100%%);
    display: flex;
    flex-direction: column;
    justify-content: flex-end;
  }
  main { max-width: 44rem; padding: 2.5rem 1.5rem 2rem; }
  .mark { letter-spacing: .38em; font-size: .72rem; font-weight: 700; text-transform: uppercase; color: #e11d2e; }
  h1 { font-size: clamp(2.2rem, 6vw, 4.2rem); line-height: .95; margin: .35rem 0 .6rem; text-transform: uppercase; font-weight: 800; text-shadow: 0 2px 0 #000; }
  p { margin: 0 0 .7rem; font-size: 1.05rem; max-width: 36rem; color: #ddd7cc; }
  .code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .8rem; color: #9a958c; }
  .cta a {
    display: inline-block; margin-top: .6rem; padding: .7rem 1.2rem;
    background: #e11d2e; color: #fff; text-decoration: none; font-weight: 700; letter-spacing: .06em; text-transform: uppercase;
  }
  footer {
    padding: .9rem 1.5rem 1.3rem;
    font-size: .78rem; color: #8c877e;
    border-top: 1px solid rgba(255,255,255,.08);
  }
  footer strong { color: #d8d2c6; font-weight: 650; }
</style>
</head>
<body>
  <div class="veil">
    <main>
      <div class="mark">FESS</div>
      <h1>%s</h1>
      <p>%s</p>
      %s
      <p class="code">HTTP %d · Frontend Security Server</p>
      %s
    </main>
    <footer>
      Стрит-арт для FESS · автор <strong>%s</strong> (%s) · Apache-2.0
    </footer>
  </div>
</body>
</html>`, title, art, brandArtFit(kind), title, lead, extraPara(extra), code, btn, fessAuthor, fessAuthorEN)
}

func extraPara(extra string) string {
	if strings.TrimSpace(extra) == "" {
		return ""
	}
	return "<p>" + extra + "</p>"
}

func maybeServeSplash(w http.ResponseWriter, r *http.Request, mr routing.MatchResult, db *sql.DB, ipRes *clientip.Resolver) bool {
	if !mr.Splash && mr.Backend != nil {
		return false
	}
	writeProxyAccessLog(r.Context(), db, r, mr, "splash", ipRes)
	writeFESSSplash(w)
	return true
}
