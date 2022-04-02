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
)

func HandleGitPull(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if keystring, ok := os.LookupEnv("WEBHOOK_SECRET"); ok {
		sig := req.Header.Get("X-Hub-Signature")
		if !strings.HasPrefix(sig, "sha1=") {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "Missing signature\n")
			return
		}
		sigmac, err := hex.DecodeString(sig[5:])
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "Invalid signature\n")
			return
		}
		key := []byte(keystring)
		mac := hmac.New(sha1.New, key)
		mac.Write(body)
		if !hmac.Equal(sigmac, mac.Sum(nil)) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "Bad signature\n")
			return
		}
	}

	var payload GitPullPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Invalid JSON\n")
		return
	}
	if payload.Ref == "refs/heads/gh-pages" {
		cmd := exec.Command("/bin/sh", "-c", "git fetch origin gh-pages && git reset --hard FETCH_HEAD")
		cmd.Dir = "/srv/www/Git"
		if err := cmd.Start(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "Webhook failed\n")
		} else {
			fmt.Fprintf(w, "OK\n")
		}
	} else {
		fmt.Fprintf(w, "Not interested in this ref\n")
	}
}

func init() {
	flag.StringVar(&listenPort, "l", "127.0.0.1:8001", "listen address and port")
	flag.StringVar(&workDir, "c", "/var/www/html", "git repo location")
}

func main() {
	flag.Parse()
	http.HandleFunc("/webhook/github/pull", HandleGitPull)
	log.Fatal(http.ListenAndServe(listenPort, nil))
}
