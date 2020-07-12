package main

// freightinterface.com frontend https server
// @dev [prodcution]; <production variable to change>
// comments: @_agent_ [type]; <content>
// To run:
// go run main.go
// Command-line options:
//   -production : enables HTTPS on port 443
//   -redirect-to-https : redirect HTTP to HTTTPS

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"https://github.com/freight-trust/interface/src/ip.go" // @dev TODO; make sure this resolves
)

const (
	htmlIndex = `<html><body>freightinterface.com</body></html>`
	httpPort  = "127.0.0.1:8080"
)

var (
	flgProduction          = false
	flgRedirectHTTPToHTTPS = false
)

type Error struct {
	Error   int    `json:"error"`
	Message string `json:"message"`
}

func main() {
	listenPort := flag.Int("port", 80, "The port to bind http server")
	listenAddr := flag.String("addr", "", "The addr to bind http server") /// @dev production; your server IP Address (public)

	// Parse command line arguments
	flag.Parse()

	// Log all the other requests and return 404
	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		log.Println(req.Proto, req.URL)

		var errorCode = 404
		var e = Error{
			Error:   errorCode,
			Message: fmt.Sprintf("Resource [%s] not found", req.URL.Path),
		}
		b, err := json.Marshal(e)
		if err != nil {
			fmt.Println("error:", err)
			http.Error(res, "Internal server Error", 500)
			return
		}

		http.Error(res, string(b), errorCode)
	})
	http.HandleFunc("/ip", ip.Handler)

	bindAddr := fmt.Sprintf("%s:%d", *listenAddr, *listenPort)
	fmt.Println(`Start listenning at "` + bindAddr + `"`)

	log.Fatal(http.ListenAndServe(bindAddr, nil))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, htmlIndex)
}

func makeServerFromMux(mux *http.ServeMux) *http.Server {
	// set timeouts so that a slow or malicious client doesn't
	// hold resources forever
	return &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      mux,
	}
}

func makeHTTPServer() *http.Server {
	mux := &http.ServeMux{}
	mux.HandleFunc("/", handleIndex)
	return makeServerFromMux(mux)

}

func makeHTTPToHTTPSRedirectServer() *http.Server {
	handleRedirect := func(w http.ResponseWriter, r *http.Request) {
		newURI := "https://" + r.Host + r.URL.String()
		http.Redirect(w, r, newURI, http.StatusFound)
	}
	mux := &http.ServeMux{}
	mux.HandleFunc("/", handleRedirect)
	return makeServerFromMux(mux)
}

func parseFlags() {
	flag.BoolVar(&flgProduction, "production", false, "if true, we start HTTPS server")
	flag.BoolVar(&flgRedirectHTTPToHTTPS, "redirect-to-https", false, "if true, we redirect HTTP to HTTPS") /// @dev production; https redirect
	flag.Parse()
}

func main() {
	parseFlags()
	var m *autocert.Manager

	var httpsSrv *http.Server
	if flgProduction {
		hostPolicy := func(ctx context.Context, host string) error {
			// @dev production; change to your real host
			allowedHost := "www.freightinterface.com"
			if host == allowedHost {
				return nil
			}
			return fmt.Errorf("acme/autocert: only %s host is allowed", allowedHost)
		}

		dataDir := "."
		m = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: hostPolicy,
			Cache:      autocert.DirCache(dataDir),
		}

		httpsSrv = makeHTTPServer()
		httpsSrv.Addr = ":443"
		httpsSrv.TLSConfig = &tls.Config{GetCertificate: m.GetCertificate}

		go func() {
			fmt.Printf("Starting HTTPS server on %s\n", httpsSrv.Addr)
			err := httpsSrv.ListenAndServeTLS("", "")
			if err != nil {
				log.Fatalf("httpsSrv.ListendAndServeTLS() failed with %s", err)
			}
		}()
	}

	var httpSrv *http.Server
	if flgRedirectHTTPToHTTPS {
		httpSrv = makeHTTPToHTTPSRedirectServer()
	} else {
		httpSrv = makeHTTPServer()
	}
	// @dev docs; allow autocert handle Let's Encrypt callbacks over http
	if m != nil {
		httpSrv.Handler = m.HTTPHandler(httpSrv.Handler)
	}

	httpSrv.Addr = httpPort
	fmt.Printf("Starting HTTP server on %s\n", httpPort)
	err := httpSrv.ListenAndServe()
	if err != nil {
		log.Fatalf("httpSrv.ListenAndServe() failed with %s", err)
	}
}