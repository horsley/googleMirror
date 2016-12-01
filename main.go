// googleMirror project main.go
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	flagConfigFile = flag.String("c", "", "config file")
)

type mirrorConfig struct {
	GoogleHosts []string //upstreams
	GoogleSSL   bool     //ssl to google host

	MirrorListen string //local service listen
	MirrorCert   string //local service using https cert
	MirrorKey    string //local service using https key

	Redirect80 string //listen 80 and redirect to this url

	Auth map[string]string //auth user:pass default no pass
}

var defaultConfig = mirrorConfig{
	GoogleHosts: []string{
		"74.125.204.147:443",
		"74.125.204.106:443",
		"74.125.204.105:443",
		"74.125.204.104:443",
		"74.125.204.103:443",
		"74.125.204.99:443",
		"64.233.189.147:443",
		"64.233.189.106:443",
		"64.233.189.105:443",
		"64.233.189.104:443",
		"64.233.189.103:443",
		"64.233.189.99:443",
		"173.194.72.147:443",
		"173.194.72.106:443",
		"173.194.72.105:443",
		"173.194.72.104:443",
		"173.194.72.103:443",
		"173.194.72.99:443",
		"64.233.187.147:443",
		"64.233.187.106:443",
		"64.233.187.105:443",
		"64.233.187.104:443",
		"64.233.187.103:443",
		"64.233.187.99:443",
		"74.125.23.147:443",
		"74.125.23.106:443",
		"74.125.23.105:443",
		"74.125.23.104:443",
		"74.125.23.103:443",
		"74.125.23.99:443",
		"64.233.188.147:443",
		"64.233.188.106:443",
		"64.233.188.105:443",
		"64.233.188.104:443",
		"64.233.188.103:443",
		"64.233.188.99:443",
	},
	GoogleSSL:    true,
	MirrorListen: ":16113",
}

var googleHostPicker func() string
var mirrorHost string
var mirrorDomain string

func init() {
	flag.Parse()
	if err := loadConfig(); err != nil {
		log.Println("loadConfig err:", err)
		os.Exit(-1)
	}
	googleHostPicker = googleHostRoundRobin()
}

func main() {
	log.Println("googleMirror server listen at", defaultConfig.MirrorListen)

	if len(defaultConfig.Auth) > 0 {
		http.HandleFunc("/", httpAuthWrapper(proxyHandler))
	} else {
		http.HandleFunc("/", proxyHandler)
	}

	if defaultConfig.Redirect80 != "" {
		log.Println("listen 80 and redirect to:", defaultConfig.Redirect80)
		go func() { http.ListenAndServe(":80", http.RedirectHandler(defaultConfig.Redirect80, http.StatusFound)) }()
	}

	if defaultConfig.MirrorCert != "" && defaultConfig.MirrorKey != "" {
		log.Println(http.ListenAndServeTLS(defaultConfig.MirrorListen, defaultConfig.MirrorCert, defaultConfig.MirrorKey, nil))
	} else {
		log.Println(http.ListenAndServe(defaultConfig.MirrorListen, nil))
	}
}

func httpAuthWrapper(h http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			rw.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(rw, "need auth", http.StatusUnauthorized)
			return
		}
		if defaultConfig.Auth[user] != pass {
			http.Error(rw, "auth failed", http.StatusUnauthorized)
			return
		}

		h(rw, r)
	}
}

func proxyHandler(rw http.ResponseWriter, r *http.Request) {
	setMirrorHost(r.Host)

	rp := &httputil.ReverseProxy{
		Director: requestFilter,
		Transport: &http.Transport{ //config from default transport
			Dial: func(network, addr string) (net.Conn, error) {
				addr = googleHostPicker() //rewrite target address
				log.Println("using google host:", addr)
				return (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).Dial(network, addr)
			},
			Proxy:                 http.ProxyFromEnvironment,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, r)
	doResponseFilter(rec, rw)
}

func requestFilter(req *http.Request) {
	host := "www.google.com" //default

	//verify host
	if strings.HasPrefix(req.URL.Path, "/ipv4") || strings.HasPrefix(req.URL.Path, "/ipv6") {
		host = req.URL.Path[1:5] + ".google.com"
		req.URL.Path = req.URL.Path[5:]
	}

	//host proxy
	if strings.HasPrefix(req.URL.Path, "/!") { //redirect
		pathParts := strings.Split(req.URL.Path[2:], "/")
		host = pathParts[0]
		req.URL.Path = "/" + strings.Join(pathParts[1:], "/")
	}

	//cookie
	if ck, err := req.Cookie("GZ"); err == nil && ck != nil {
		ck.Value = "Z=0"
	}

	//url args
	query := req.URL.Query()
	query.Set("gws_rd", "cr")
	req.URL.RawQuery = query.Encode()

	if defaultConfig.GoogleSSL {
		req.URL.Scheme = "https"
	} else {
		req.URL.Scheme = "http"
	}
	req.URL.Host = host
	req.Host = host
	//	req.Header.Set("Accept-Language", "zh-CN")
	req.Header.Set("Accept-Encoding", "") //so we can do plan text replace
}

func doResponseFilter(rec *httptest.ResponseRecorder, rw http.ResponseWriter) {
	//body first, we need modify the body and get new content-length
	originBody := rec.Body.Bytes()
	var replacedBody []byte

	if strings.Contains(rec.Header().Get("Content-Type"), "image/") {
		//not do replace with bin
		replacedBody = originBody
	} else {
		replacedBody = responseBodyReplacement(originBody)
	}

	//header filter
	replacedHeader := responseHeaderReplacement(rec.Header(), len(replacedBody))
	for k, v := range replacedHeader {
		rw.Header()[k] = v
	}

	rw.WriteHeader(rec.Code)
	rw.Write(replacedBody)
}

var (
	replaceRegexp1 = regexp.MustCompile(`(?i)([0-9A-Za-z.-]+\.gstatic\.com)`)
	replaceRegexp2 = regexp.MustCompile(`(?i)(apis\.google\.com)`)
	replaceRegexp3 = regexp.MustCompile(`(?i)((www|images)\.google\.[0-9a-z.]+)`)
)

func responseHeaderReplacement(origin http.Header, contentLength int) http.Header {
	result := make(http.Header)

	for k, v := range origin {
		if strings.EqualFold(k, "Location") {
			redirect, err := url.Parse(v[0])
			if err == nil {
				if strings.Contains(redirect.Host, "google") {
					if strings.Contains(redirect.Host, "ipv") {
						redirect.Path = "/" + redirect.Host[:4] + redirect.Path
						log.Println("warning! seems we meet the verify code page")
					}

					//@todo: scheme
					redirect.Host = mirrorHost
					v[0] = redirect.String()
				}
			}
		} else if strings.EqualFold(k, "Set-Cookie") {
			kvs := explodeKV(v[0], ";")
			for i, kv := range kvs {
				if strings.EqualFold(kv.k, "domain") {
					kvs[i].v = mirrorDomain
				} else if strings.EqualFold(kv.k, "path") {
					kvs[i].v = "/"
				}
			}
			v[0] = implodeKV(kvs, "; ")
		} else if strings.EqualFold(k, "Content-Length") {
			v[0] = fmt.Sprint(contentLength)
		}

		result[k] = v
	}
	return result
}

func responseBodyReplacement(origin []byte) []byte {
	hostTarget := []byte(mirrorHost)
	hostTargetRedirect := []byte(mirrorHost + "/!$1")

	result := replaceRegexp1.ReplaceAll(origin, hostTargetRedirect)
	result = replaceRegexp2.ReplaceAll(result, hostTargetRedirect)
	result = replaceRegexp3.ReplaceAll(result, hostTarget)

	var mirrorScheme, oppsiteScheme string
	if defaultConfig.GoogleSSL {
		mirrorScheme = "https"
		oppsiteScheme = "http"
	} else {
		mirrorScheme = "http"
		oppsiteScheme = "https"
	}
	domainRe := regexp.MustCompile("(?i)" + oppsiteScheme + "://" + mirrorHost)
	result = domainRe.ReplaceAll(result, []byte(mirrorScheme+"://"+mirrorHost))

	return result
}

func googleHostRoundRobin() func() string {
	counter := 0
	return func() string {
		counter++
		return defaultConfig.GoogleHosts[counter%len(defaultConfig.GoogleHosts)]
	}
}

func loadConfig() error {
	if *flagConfigFile == "" {
		return nil //use default config
	}

	f, err := os.Open(*flagConfigFile)
	if err != nil {
		return err
	}
	defer f.Close()

	j := json.NewDecoder(f)

	var configFromFile mirrorConfig
	err = j.Decode(&configFromFile)
	if err != nil {
		return err
	}

	//little check
	if len(configFromFile.GoogleHosts) < 1 {
		return errors.New("no google host in config")
	}

	defaultConfig = configFromFile
	return nil
}

func setMirrorHost(host string) {
	if mirrorHost == "" {
		mirrorHost = host

		if strings.Contains(mirrorHost, ":") { //an ip:port
			mirrorDomain = mirrorHost[:strings.Index(mirrorHost, ":")]
		} else {
			mirrorDomain = mirrorHost
		}
	}
}

type kv struct {
	k, v string
}

func explodeKV(src, sepr string) []kv {
	kvs := strings.Split(src, sepr)

	result := make([]kv, 0)
	for _, kvStr := range kvs {
		kvPair := strings.Split(kvStr, "=")

		var kvItem kv
		kvItem.k = strings.TrimSpace(kvPair[0])
		if len(kvPair) < 2 {
			kvItem.v = ""
		} else {
			kvItem.v = strings.TrimSpace(strings.Join(kvPair[1:], "="))
		}

		result = append(result, kvItem)
	}
	return result
}

func implodeKV(kv []kv, sepr string) string {
	kvs := make([]string, 0)
	for _, kv := range kv {
		if kv.v == "" {
			kvs = append(kvs, kv.k)
		} else {
			kvs = append(kvs, kv.k+"="+kv.v)
		}
	}
	return strings.Join(kvs, sepr)
}
