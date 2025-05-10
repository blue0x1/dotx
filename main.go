package main

/*
     _                  
    | |      _          
  _ | | ___ | |_  _   _ 
 / || |/ _ \|  _)( \ / )
( (_| | |_| | |__ ) X ( 
 \____|\___/ \___|_/ \_)
 
 Security scanner by chokri hammedi (@blue0x1)
https://github.com/blue0x1
*/


import (
	
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	ua           = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	depthDefault = 2
)

var (
	showVersion bool
    versionFlag string
	target    string
	threads   = 20
	client    *http.Client
	seen      = make(map[string]bool)
	seenLock  = &sync.Mutex{}
	fileCheck = []string{
    ".env", ".env.prod", ".env.local", ".env.dev", ".env.test", 
    ".env.backup", ".env.swp", ".env~", ".env.save",
    ".git/config", ".git/HEAD", ".git/logs/HEAD", ".git-credentials",
    ".htaccess", ".htpasswd", ".bash_history", ".bash_profile", ".bashrc",
    ".ssh/id_rsa", ".ssh/id_rsa.pub", ".ssh/authorized_keys", ".ssh/config",
    ".npmrc", ".dockercfg", ".docker/config.json", ".aws/credentials", ".netrc",
    ".npmignore", ".eslintrc", ".prettierrc", ".babelrc",
    ".travis.yml", ".circleci/config.yml", ".github/workflows/*.yml",
    "config/database.yml", "config/secrets.yml", "config/credentials.yml.enc",
    "Gemfile", "Gemfile.lock", "config/master.key", "config/initializers/secret_token.rb",
    "db/schema.rb", "db/production.sqlite3", "config/database.example.yml",
    "static../config/cable.yml", "public../config/database.yml",
    "assets../../config/secrets.yml", "javascripts..%2f..%2fconfig/credentials.yml.enc",
    "static%2e%2e/config/cable.yml", "public%2e%2e%2fconfig/database.yml",
    "assets%2e%2e%2f%2e%2e%2fconfig/secrets.yml", "stylesheets..%252f..%252fconfig/master.key",
    "package.json", "package-lock.json", "yarn.lock", ".nvmrc",
    "next.config.js", "nuxt.config.js", "config.js", "server.js", "app.js",
    ".next/server/pages-manifest.json", ".next/routes-manifest.json",
    "public/..%2f..%2fpackage-lock.json", "build/..%2f..%2fnext.config.js",
    "settings.py", "local_settings.py", "config/settings.py",
    "requirements.txt", "requirements-dev.txt", "pip.conf",
    "instance/config.py", "wsgi.py", "manage.py", "config.py",
    "media/..%2f..%2fsettings.py", "static/%2e%2e/%2e%2frequirements.txt",
    "wp-config.php", "configuration.php", "config.php",
    "wp-content/..%2f..%2fwp-config.php", "assets%%2e%%2e%%2fconfig.php.bak",
    "config.php.bak", "config.php.old", "config.php.save", "config.php~",
    "WEB-INF/web.xml", "WEB-INF/classes/application.properties",
    "application.yml", "application-dev.yml", "application-prod.yml",
    "spring.properties", "applicationContext.xml", "spring-config.xml",
    "/javax.faces.resource.../WEB-INF/classes/spring/application-context.xml.jsf",
    "/javax.faces.resource.../WEB-INF/web.xml.jsf",
    "/javax.faces.resource.../WEB-INF/classes/application.properties.jsf",
    "/javax.faces.resource.../META-INF/persistence.xml.jsf",
    "/javax.faces.resource.../WEB-INF/classes/database.properties.jsf",
    "/javax.faces.resource.../WEB-INF/classes/config/security.xml.jsf",
    "/javax.faces.resource%2e%2e%2f/WEB-INF/web.xml.jsf",
    "/javax.faces.resource..%252fWEB-INF%252fclasses%252fspring%252fapplication-context.xml.jsf",
    "/javax.faces.resource....////WEB-INF////classes////spring////application-context.xml.jsf",
    "/faces/javax.faces.resource.../WEB-INF/web.xml",
    "/faces/javax.faces.resource.../WEB-INF/classes/application.properties",
    "?javax.faces.resource=.../WEB-INF/classes/config.xml",
    "/resources.../WEB-INF/web.xml",
    "/static.../WEB-INF/classes/spring/application-context.xml",
    "/assets..%2f..%2fWEB-INF%2fweb.xml",
    "/public..%2f..%2fMETA-INF%2fcontext.xml",
    "/actuator/env",
    "/actuator/configprops",
    "/actuator/health",
    "/actuator/info",
    "/actuator/mappings",
    "/actuator/beans",
    "/actuator/httptrace",
    "/faces/javax.faces.resource.../WEB-INF/faces-config.xml",
    "/faces/javax.faces.resource.../META-INF/maven/pom.xml",
    "/javax.faces.resource.../WEB-INF/lib/",
    "/javax.faces.resource.../WEB-INF/classes/log4j.properties",
    "/.git/HEAD",
    "/.svn/entries",
    "/.hg/store",
    "/WEB-INF/web.xml.bak",
    "/META-INF/context.xml.old",
    "dump.sql", "backup.sql", "database.sql", "prod.sql",
    "database.db", "app.db", "users.db", "auth.db",
    "db.sqlite", "db.sqlite3", "data.sqlite",
    ".github/workflows/deploy.yml", ".github/settings.yml",
    "Jenkinsfile", "Dockerfile", "docker-compose.yml",
    "build.gradle", "pom.xml", "build.xml",
    "backup.bak", "config.bak", "database.bak",
    "config.old", "settings.old", "database.old",
    "backup.zip", "snapshot.7z", "prod-db.zip",
    "error.log", "access.log", "debug.log",
    "laravel.log", "production.log",
    "....//....//etc/passwd", "..\\\\..\\\\database.sql",
    "%2e%2e%2f%2e%2e%2f.git/HEAD", "..%252f..%252fetc%252fshadow",
    "%252e%252e%252f%252e%252e%252f.env", "..%c0%af..%c0%af.bash_history",
    "download?file=....//config/master.key",
    "export?path=static../settings.py",
    "image?src=..%2f..%2f.aws/credentials",
    "storage/framework/.env", "bootstrap/cache/config.php",
    ".next/server/pages-manifest.json", "app/config/parameters.yml",
    "web.config", "applicationHost.config",
    "inetpub\\logs\\LogFiles",
    ".kube/config", ".docker/config.json",
    "gcp/credentials.json", "azure/config",
    "phpinfo.php", "test.php", "info.php",
    "composer.json", "composer.lock",
    "Procfile", "restart.txt",
}
	secretCheck = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bAKIA[0-9A-Z]{16}\b`),
		regexp.MustCompile(`(?i)\bgh[pus]_[A-Za-z0-9]{36}\b`),
		regexp.MustCompile(`(?i)\bsk_(live|test)_[a-z0-9]{24}\b`),
		regexp.MustCompile(`(?i)\bxox[baprs]-[0-9a-zA-Z]{10,48}\b`),
		regexp.MustCompile(`(?i)(password|passwd)[=:]['"]?[^'"\s]{8,64}`),
	}
)


type result struct {
	Tool  string   `json:"tool"`
	Url   string   `json:"url"`
	Code  int      `json:"code"`
	Found []string `json:"found,omitempty"`
	Links []string `json:"links,omitempty"`
}

func main() {
    var out string
    var d int
    var filterCode int

    flag.IntVar(&threads, "t", 20, "threads")
    flag.IntVar(&d, "d", depthDefault, "depth")
    flag.StringVar(&out, "o", "", "output")
    flag.IntVar(&filterCode, "code", 0, "filter by HTTP status code (0 shows all)")
    flag.BoolVar(&showVersion, "version", false, "Show version")
    flag.BoolVar(&showVersion, "v", false, "Show version (shorthand)")
    
    flag.Usage = func() {
        fmt.Fprintf(os.Stderr, `
     _                  
    | |      _          
  _ | | ___ | |_  _   _ 
 / || |/ _ \|  _)( \ / )
( (_| | |_| | |__ ) X ( 
 \____|\___/ \___|_/ \_)
 
Usage:
`)
        flag.PrintDefaults()
    }

    flag.Parse()

    if showVersion {
        fmt.Println(`
     _                  
    | |      _          
  _ | | ___ | |_  _   _ 
 / || |/ _ \|  _)( \ / )
( (_| | |_| | |__ ) X ( 
 \____|\___/ \___|_/ \_)
`)
        fmt.Println("dotx v1.0 - Dotfile scanner")
        os.Exit(0)
    }

    if flag.NArg() < 1 {
        flag.Usage()
        os.Exit(1)
    }

    target = fixUrl(flag.Arg(0))
    client = mkClient()

    results := make(chan result)
    var wg sync.WaitGroup

    // Create output file immediately
    var file *os.File
    var err error
    if out != "" {
        file, err = os.Create(out)
        if err != nil {
            fmt.Fprintf(os.Stderr, "dotx error creating file: %v\n", err)
            os.Exit(1)
        }
        defer file.Close()
    }

    wg.Add(1)
    go func() {
        defer wg.Done()
        scan(target, d, client, results, &wg)
    }()

    go func() {
        wg.Wait()
        close(results)
    }()

    displayed := make(map[string]bool)
    for r := range results {
        if _, exists := displayed[r.Url]; !exists && (filterCode == 0 || r.Code == filterCode) {
            displayed[r.Url] = true
            showResult(r, filterCode)
            
            // Write to file immediately with error handling
            if file != nil {
                err := json.NewEncoder(file).Encode(r)
                if err != nil {
                    fmt.Fprintf(os.Stderr, "dotx error writing to %s: %v\n", out, err)
                }
                file.Sync() // Force write to disk
            }
        }
    }
}

func scan(u string, max int, c *http.Client, ch chan<- result, wg *sync.WaitGroup) {
    seenLock.Lock()
    if seen[u] {
        seenLock.Unlock()
        return
    }
    seen[u] = true
    seenLock.Unlock()

    var levelWG sync.WaitGroup

   
    for _, p := range fileCheck {
        full := buildUrl(u, p)
        res := checkUrl(full, c)
        if res.Code == 200 || res.Code == 403 {
            ch <- res
        }
    }

  
    if max > 0 {
        baseRes := checkUrl(u, c)
        if baseRes.Code == 200 {
            ch <- baseRes

            links := getLinks(baseRes.Url, baseRes.Links)
            levelWG.Add(len(links))

            for _, l := range links {
                go func(link string) {
                    defer levelWG.Done()
                    seenLock.Lock()
                    if !seen[link] {
                        seen[link] = true
                        seenLock.Unlock()
                        wg.Add(1)
                        scan(link, max-1, c, ch, wg)
                    } else {
                        seenLock.Unlock()
                    }
                }(l)
            }
        }
    }
    levelWG.Wait()
}

func checkUrl(u string, c *http.Client) result {
    
	r := result{
        Tool: "dotx",   
        Url:  u,
    }

	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", ua)

	resp, err := c.Do(req)
	if err != nil {
		return r
	}
	defer resp.Body.Close()

	r.Code = resp.StatusCode
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 200 {
		r.Found = findSecrets(string(body))
	}

	if strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		r.Links = extractLinks(string(body))
	}

	return r
}

func buildUrl(base, p string) string {
	if strings.HasPrefix(p, "./") {
		p = p[2:]
	}

	u, _ := url.Parse(base)
	if strings.HasPrefix(p, "/") {
		u.Path = p
	} else {
		u.Path = filepath.Join(u.Path, p)
	}
	return u.String()
}

func getLinks(base string, ls []string) []string {
	var valid []string
	b, _ := url.Parse(base)

	for _, l := range ls {
		if strings.HasPrefix(l, "#") || strings.HasPrefix(l, "mailto:") {
			continue
		}

		lurl, err := url.Parse(l)
		if err != nil {
			continue
		}

		full := b.ResolveReference(lurl)
		if full.Host == b.Host {
			valid = append(valid, full.String())
		}
	}
	return valid
}

func extractLinks(s string) []string {
	var ls []string
	re := regexp.MustCompile(`(?i)<a[^>]+href=["']([^"']+)["']`)
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		if len(m) > 1 {
			ls = append(ls, m[1])
		}
	}
	return ls
}

func findSecrets(s string) []string {
	var f []string
	for _, p := range secretCheck {
		ms := p.FindAllString(s, -1)
		for _, m := range ms {
			if !contains(f, m) {
				f = append(f, m)
			}
		}
	}
	return f
}

func mkClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 15 * time.Second,
	}
}

func showResult(r result, filterCode int) {
	if filterCode != 0 && r.Code != filterCode {
		return
	}

	color := "0"
	switch {
	case r.Code == 200:
		color = "32"
	case r.Code == 403 || r.Code == 401:
		color = "31"
	case r.Code >= 500:
		color = "33"
	}

	fmt.Printf("\033[%sm[%d] dotx >\033[0m %s\n", color, r.Code, r.Url)
	if len(r.Found) > 0 {
		fmt.Println("  \033[31mFOUND:\033[0m")
		for _, s := range r.Found {
			fmt.Printf("  → %s\n", s)
		}
	}
}

func fixUrl(s string) string {
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	return strings.TrimRight(s, "/")
}

func contains(sl []string, s string) bool {
	for _, x := range sl {
		if x == s {
			return true
		}
	}
	return false
}
