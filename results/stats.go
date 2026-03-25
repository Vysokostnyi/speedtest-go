package results

import (
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/go-chi/render"
	log "github.com/sirupsen/logrus"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/librespeed/speedtest-go/config"
	"github.com/librespeed/speedtest-go/database"
	"github.com/librespeed/speedtest-go/database/schema"
)

type StatsData struct {
	NoPassword bool
	LoggedIn   bool
	Data       []schema.TelemetryData
}

var (
	key   = []byte(securecookie.GenerateRandomKey(32))
	store = sessions.NewCookieStore(key)
	conf = config.LoadedConfig()
)

func init() {
	store.Options = &sessions.Options{
		Path:     conf.BaseURL+"/stats",
		MaxAge:   3600 * 1, // 1 hour
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

func Stats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t, err := template.New("stats").Parse(statsTemplate)
	if err != nil {
		log.Errorf("Failed to parse template: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if conf.DatabaseType == "none" {
		render.PlainText(w, r, "Statistics are disabled")
		return
	}

	var data StatsData

	if conf.StatsPassword == "PASSWORD" {
		data.NoPassword = true
	}

	if !data.NoPassword {
		op := r.FormValue("op")
		session, _ := store.Get(r, "logged")
		auth, ok := session.Values["authenticated"].(bool)

		if auth && ok {
			if op == "logout" {
				session.Values["authenticated"] = false
				session.Options.MaxAge = -1
				session.Save(r, w)
				http.Redirect(w, r, conf.BaseURL+"/stats", http.StatusTemporaryRedirect)
			} else {
				data.LoggedIn = true

				id := r.FormValue("id")
				switch id {
				case "L100":
					stats, err := database.DB.FetchLast100()
					if err != nil {
						log.Errorf("Error fetching data from database: %s", err)
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					data.Data = stats
				case "":
				default:
					stat, err := database.DB.FetchByUUID(id)
					if err != nil {
						log.Errorf("Error fetching data from database: %s", err)
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					data.Data = append(data.Data, *stat)
				}
			}
		} else {
			if op == "login" {
				session, _ := store.Get(r, "logged")
				password := r.FormValue("password")
				if password == conf.StatsPassword {
					session.Values["authenticated"] = true
					session.Save(r, w)
					http.Redirect(w, r, conf.BaseURL+"/stats", http.StatusTemporaryRedirect)
				} else {
					w.WriteHeader(http.StatusForbidden)
				}
			}
		}
	}

	if err := t.Execute(w, data); err != nil {
		log.Errorf("Error executing template: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

type ProcessedResult struct {
	UUID      string
	Timestamp string
	IPAddress string
	ISPInfo   string
	Download  string
	Upload    string
	Ping      string
	Jitter    string
	NotFound  bool
}

func parseISP(ispJson string) string {
	var result struct {
		ProcessedString string `json:"processedString"`
	}
	if err := json.Unmarshal([]byte(ispJson), &result); err != nil {
		return ispJson // Fallback to raw if parsing fails
	}
	return result.ProcessedString
}

func ShowResult(w http.ResponseWriter, r *http.Request) {
	uuid := r.FormValue("id")
	if uuid == "" {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t, t_err := template.New("result").Parse(resultTemplate)
	if t_err != nil {
		log.Errorf("Failed to parse template: %s", t_err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	record, err := database.DB.FetchByUUID(uuid)
	if err != nil {
		// Not found or DB error - render empty state
		t.Execute(w, ProcessedResult{NotFound: true})
		return
	}

	processed := ProcessedResult{
		UUID:      record.UUID,
		Timestamp: record.Timestamp.Format("2006-01-02 15:04:05"),
		IPAddress: record.IPAddress,
		ISPInfo:   parseISP(record.ISPInfo),
		Download:  record.Download,
		Upload:    record.Upload,
		Ping:      record.Ping,
		Jitter:    record.Jitter,
	}

	if err := t.Execute(w, processed); err != nil {
		log.Errorf("Error executing result template: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

const commonStyle = `
	:root {
		--primary: #6366f1;
		--bg: #0f172a;
		--card-bg: rgba(30, 41, 59, 0.7);
		--text: #f8fafc;
		--text-muted: #94a3b8;
		--glass-border: rgba(255, 255, 255, 0.1);
	}
	* { box-sizing: border-box; margin: 0; padding: 0; }
	body {
		font-family: 'Outfit', -apple-system, sans-serif;
		background: var(--bg);
		background-image: radial-gradient(at 50% 0%, hsla(225,39%,30%,1) 0, transparent 50%);
		color: var(--text);
		min-height: 100vh;
		padding: 40px 20px;
		display: flex;
		flex-direction: column;
		align-items: center;
	}
	.glass-card {
		background: var(--card-bg);
		backdrop-filter: blur(12px);
		border: 1px solid var(--glass-border);
		border-radius: 24px;
		padding: 30px;
		width: 100%;
		max-width: 800px;
		box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
	}
	h1 { margin-bottom: 30px; text-align: center; background: linear-gradient(to right, #6366f1, #a855f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
	input[type="text"], input[type="password"] {
		background: rgba(0, 0, 0, 0.2);
		border: 1px solid var(--glass-border);
		color: white;
		padding: 10px 15px;
		border-radius: 8px;
		margin: 5px;
	}
	input[type="submit"], button {
		background: var(--primary);
		border: none;
		color: white;
		padding: 10px 20px;
		border-radius: 8px;
		cursor: pointer;
		margin: 5px;
		transition: opacity 0.2s;
	}
	table { width: 100%; border-collapse: collapse; margin-top: 20px; background: rgba(0,0,0,0.1); border-radius: 12px; overflow: hidden; }
	th, td { padding: 12px; text-align: left; border-bottom: 1px solid var(--glass-border); }
	th { color: var(--text-muted); font-weight: 300; width: 30%; }
	.toast {
		position: fixed;
		bottom: 30px;
		left: 50%;
		transform: translateX(-50%) translateY(100px);
		background: linear-gradient(135deg, var(--primary), #a855f7);
		color: white;
		padding: 12px 24px;
		border-radius: 99px;
		box-shadow: 0 10px 25px rgba(0,0,0,0.3);
		z-index: 1000;
		transition: all 0.5s cubic-bezier(0.68, -0.55, 0.265, 1.55);
		opacity: 0;
		pointer-events: none;
		font-weight: 500;
	}
	.toast.show { transform: translateX(-50%) translateY(0); opacity: 1; }
`

const statsTemplate = `<!DOCTYPE html>
<html>
<head>
	<title>Flow Access - Статистика</title>
	<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600&display=swap" rel="stylesheet">
	<style>` + commonStyle + `</style>
</head>
<body>
	<h1>Статистика серверов</h1>
	<main class="glass-card">
	{{ if .NoPassword }}
		<p style="color: #ef4444; text-align: center;">Пожалуйста, установите statistics_password в settings.toml для доступа.</p>
	{{ else if .LoggedIn }}
		<div style="display: flex; justify-content: space-between; margin-bottom: 20px;">
			<form action="stats" method="GET">
				<input type="text" name="id" id="id" placeholder="ID теста" />
				<input type="submit" value="Найти" />
				<button type="button" onclick="document.getElementById('id').value='L100'; this.form.submit();">Последние 100</button>
			</form>
			<form action="stats" method="GET"><input type="hidden" name="op" value="logout" /><input type="submit" value="Выйти" style="background: #ef4444;" /></form>
		</div>

		{{ range $i, $v := .Data }}
		<div style="margin-bottom: 30px; background: rgba(255,255,255,0.03); padding: 20px; border-radius: 16px; position: relative;">
			<h4 style="margin-bottom: 10px; color: var(--primary);">Результат #{{ $v.UUID }}</h4>
			<button onclick="copyLink('{{ $v.UUID }}')" style="position: absolute; top: 15px; right: 20px; background: rgba(255,255,255,0.1); border: none; color: white; padding: 5px 12px; border-radius: 8px; cursor: pointer; font-size: 0.8rem;">Копировать ссылку</button>
			<table>
				<tr><th>Дата</th><td>{{ $v.Timestamp.Format "2006-01-02 15:04:05" }}</td></tr>
				<tr><th>IP / ISP</th><td>{{ $v.IPAddress }}</td></tr>
				<tr><th>Download</th><td style="color: #22d3ee; font-weight: 600;">{{ $v.Download }} Mbps</td></tr>
				<tr><th>Upload</th><td style="color: #818cf8; font-weight: 600;">{{ $v.Upload }} Mbps</td></tr>
				<tr><th>Ping / Jitter</th><td>{{ $v.Ping }} / {{ $v.Jitter }} ms</td></tr>
			</table>
		</div>
		{{ else }}
			<p style="text-align: center; color: var(--text-muted);">Нет данных для отображения</p>
		{{ end }}
	{{ else }}
		<form action="stats?op=login" method="POST" style="text-align: center;">
			<h3 style="margin-bottom: 15px;">Вход в систему</h3>
			<input type="password" name="password" placeholder="Пароль" autofocus />
			<input type="submit" value="Войти" />
		</form>
	{{ end }}
	</main>
	<div id="toast" class="toast">Ссылка скопирована!</div>
	<script>
		function copyLink(id) {
			const url = window.location.origin + "/results/?id=" + id;
			navigator.clipboard.writeText(url).then(() => {
				showToast("Ссылка скопирована!");
			});
		}
		function showToast(msg) {
			const t = document.getElementById("toast");
			t.innerText = msg;
			t.className = "toast show";
			setTimeout(() => { t.className = "toast"; }, 2500);
		}
	</script>
</body>
</html>`

const resultTemplate = `<!DOCTYPE html>
<html>
<head>
	<title>Результаты теста - Flow Access</title>
	<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600&display=swap" rel="stylesheet">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<style>` + commonStyle + `
		.result-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px; }
		.val { font-size: 2rem; font-weight: 600; }
		.unit { font-size: 0.9rem; color: var(--text-muted); }
	</style>
</head>
<body>
	<h1>Результат теста</h1>
	<main class="glass-card">
		{{ if .UUID }}
		<div style="text-align: center; margin-bottom: 30px;">
			<div style="font-size: 0.8rem; color: var(--text-muted);">ID: {{ .UUID }}</div>
			<div style="font-size: 0.9rem;">{{ .Timestamp }}</div>
		</div>

		<div class="result-grid">
			<div style="text-align: center; padding: 15px; background: rgba(255,255,255,0.05); border-radius: 16px;">
				<div class="unit">Download</div>
				<div class="val" style="color: #22d3ee;">{{ .Download }}</div>
				<div class="unit">Mbps</div>
			</div>
			<div style="text-align: center; padding: 15px; background: rgba(255,255,255,0.05); border-radius: 16px;">
				<div class="unit">Upload</div>
				<div class="val" style="color: #818cf8;">{{ .Upload }}</div>
				<div class="unit">Mbps</div>
			</div>
			<div style="text-align: center; padding: 15px; background: rgba(255,255,255,0.05); border-radius: 16px;">
				<div class="unit">Ping</div>
				<div class="val" style="color: #fca311;">{{ .Ping }}</div>
				<div class="unit">ms</div>
			</div>
			<div style="text-align: center; padding: 15px; background: rgba(255,255,255,0.05); border-radius: 16px;">
				<div class="unit">Jitter</div>
				<div class="val" style="color: #fca311;">{{ .Jitter }}</div>
				<div class="unit">ms</div>
			</div>
		</div>

		<div style="margin-top: 30px; padding: 15px; border-top: 1px solid var(--glass-border); font-size: 0.9rem; text-align: center;">
			<div style="color: var(--text-muted);">{{ .IPAddress }}</div>
			<div style="margin-top: 5px;">{{ .ISPInfo }}</div>
		</div>
		{{ else }}
		<div style="text-align: center; padding: 40px 20px;">
			<div style="font-size: 4rem; margin-bottom: 20px;">🛰️</div>
			<h2 style="margin-bottom: 15px;">Результат не найден</h2>
			<p style="color: var(--text-muted);">Тест с таким ID не существует или был удален.</p>
		</div>
		{{ end }}

		<div style="margin-top: 30px; text-align: center;">
			<button onclick="copyThis()" style="background: var(--primary); border: none; color: white; padding: 12px 24px; border-radius: 12px; cursor: pointer; font-weight: 600; width: 100%; margin-bottom: 15px;">Поделиться результатом</button>
			<a href="/" style="color: var(--primary); text-decoration: none; font-weight: 600;">На главную</a>
		</div>
	</main>
	<div id="toast" class="toast">Ссылка скопирована!</div>
	<script>
		function copyThis() {
			navigator.clipboard.writeText(window.location.href).then(() => {
				showToast("Ссылка скопирована!");
			});
		}
		function showToast(msg) {
			const t = document.getElementById("toast");
			t.innerText = msg;
			t.className = "toast show";
			setTimeout(() => { t.className = "toast"; }, 2500);
		}
	</script>
</body>
</html>`
