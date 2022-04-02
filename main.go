package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

type GitPullPayload struct {
	Ref string `json:"ref"`
}

var (
	listenPort string
	workDir    string
	urlPath    string
)

func HandleGitPull(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Printf("ioutil.Readall failed: %s\n", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if keystring, ok := os.LookupEnv("WEBHOOK_SECRET"); ok {
		sig := req.Header.Get("X-Hub-Signature")
		if !strings.HasPrefix(sig, "sha1=") {
			log.Printf("Missing signature\n")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "Missing signature\n")
			return
		}
		sigmac, err := hex.DecodeString(sig[5:])
		if err != nil {
			log.Printf("Invalid signature: %s\n", err)
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "Invalid signature\n")
			return
		}
		mac := hmac.New(sha1.New, []byte(keystring))
		mac.Write(body)
		if !hmac.Equal(sigmac, mac.Sum(nil)) {
			log.Printf("Bad signature: Expected %x, got %x\n", mac.Sum(nil), sigmac)
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "Bad signature\n")
			return
		}
	}

	var payload GitPullPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		log.Printf("Invalid JSON: %s\n", err)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Invalid JSON\n")
		return
	}
	if payload.Ref == "refs/heads/gh-pages" {
		cmd := exec.Command("/bin/sh", "-c", "git fetch origin gh-pages && git reset --hard FETCH_HEAD")
		cmd.Dir = workDir
		if err := cmd.Start(); err != nil {
			log.Printf("exec.Command failed: %s\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "Webhook failed\n")
		} else {
			fmt.Fprintf(w, "OK\n")
		}
	} else {
		log.Printf("Ignoring ref %s\n", payload.Ref)
		fmt.Fprintf(w, "Not interested in this ref\n")
	}
}

func init() {
	flag.StringVar(&listenPort, "l", "127.0.0.1:8001", "listen address and port")
	flag.StringVar(&workDir, "c", "/var/www/html", "git repo location")
	flag.StringVar(&urlPath, "p", "/webhook/github/pull", "url path")
}

func main() {
	flag.Parse()
	// $INVOCATION_ID is set by systemd v232+
	if _, ok := os.LookupEnv("INVOCATION_ID"); ok {
		log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
	}

	http.HandleFunc(urlPath, HandleGitPull)
	log.Fatal(http.ListenAndServe(listenPort, nil))
}
