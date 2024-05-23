package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"sigs.k8s.io/yaml"
)

type HookConfig struct {
	URLPath string `json:"url-path"`
	WorkDir string `json:"working-directory"`
	Command string `json:"command"`

	// Optional settings
	Branch string `json:"branch"`
	Secret string `json:"secret"`
	Wait   bool   `json:"wait"`
}

type Config struct {
	ListenAddress string `json:"listen-address"`
	PathPrefix    string `json:"path-prefix"`

	Hooks []HookConfig `json:"hooks"`
}

type GitHubPayload struct {
	Ref string `json:"ref"`
}

type HookHandler struct {
	workDir string
	secret  string
	cmdline string
	branch  string

	mu  sync.Mutex
	cmd *exec.Cmd
}

func NewHook(c HookConfig) *HookHandler {
	h := &HookHandler{
		workDir: c.WorkDir,
		secret:  c.Secret,
		cmdline: c.Command,
		branch:  c.Branch,
	}
	if h.branch == "" {
		h.branch = "master"
	}
	return h
}

func (h *HookHandler) startCmd(cmd *exec.Cmd) error {
	if !h.mu.TryLock() {
		return fmt.Errorf("already running")
	}
	if err := cmd.Start(); err != nil {
		h.mu.Unlock()
		return err
	}
	h.cmd = cmd
	return nil
}

func (h *HookHandler) stopCmd() {
	h.cmd.Wait()
	h.cmd = nil
	h.mu.Unlock()
}

func (h *HookHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.Printf("ioutil.Readall failed: %s\n", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if h.secret != "" {
		sig := req.Header.Get("X-Hub-Signature")
		if !strings.HasPrefix(sig, "sha1=") {
			log.Printf("Missing signature\n")
			http.Error(w, "Missing signature\n", http.StatusForbidden)
			return
		}
		sigmac, err := hex.DecodeString(sig[5:])
		if err != nil {
			log.Printf("Invalid signature: %s\n", err)
			http.Error(w, "Invalid signature\n", http.StatusForbidden)
			return
		}
		mac := hmac.New(sha1.New, []byte(h.secret))
		mac.Write(body)
		if !hmac.Equal(sigmac, mac.Sum(nil)) {
			log.Printf("Bad signature: Expected %x, got %x\n", mac.Sum(nil), sigmac)
			http.Error(w, "Bad signature\n", http.StatusForbidden)
			return
		}
	}

	var payload GitHubPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		log.Printf("Invalid JSON: %s\n", err)
		http.Error(w, "Invalid JSON\n", http.StatusBadRequest)
		return
	}
	if payload.Ref != "refs/heads/"+h.branch {
		log.Printf("Ignoring ref %s\n", payload.Ref)
		http.Error(w, "Not interested in this ref\n", http.StatusOK)
		return
	}

	cmdline := h.cmdline
	if cmdline == "" {
		cmdline = fmt.Sprintf("git fetch origin %s && git reset --hard FETCH_HEAD", h.branch)
	}
	cmd := exec.Command("/bin/sh", "-c", cmdline)
	cmd.Dir = h.workDir
	if err := h.startCmd(cmd); err != nil {
		log.Printf("exec.Command failed: %s\n", err)
		http.Error(w, "Webhook failed\n", http.StatusInternalServerError)
	} else {
		defer h.stopCmd()
		http.Error(w, "OK\n", http.StatusOK)
	}
}

func loadConfigJSON(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	config := new(Config)
	if err := json.NewDecoder(f).Decode(config); err != nil {
		return nil, err
	}
	return config, nil
}

func loadConfigYAML(path string) (*Config, error) {
	d, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	config := new(Config)
	if err := yaml.Unmarshal(d, config); err != nil {
		return nil, err
	}
	return config, nil
}

func loadConfig(path string) (*Config, error) {
	switch filepath.Ext(path) {
	case ".json":
		return loadConfigJSON(path)
	case ".yaml", ".yml":
		return loadConfigYAML(path)
	default:
		return nil, fmt.Errorf("unknown config file format: %s", path)
	}
}

func main() {
	var configFile string
	flag.StringVar(&configFile, "config", "config.json", "Path to config file (JSON or YAML)")
	flag.Parse()

	// $INVOCATION_ID is set by systemd v232+
	if _, ok := os.LookupEnv("INVOCATION_ID"); ok {
		log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
	}

	config, err := loadConfig(configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %s\n", err)
	}
	if config.ListenAddress == "" {
		config.ListenAddress = ":8080"
	}

	mux := http.NewServeMux()
	for _, hook := range config.Hooks {
		h := NewHook(hook)
		mux.Handle(hook.URLPath, h)
	}
	handler := http.StripPrefix(config.PathPrefix, mux)
	log.Fatal(http.ListenAndServe(config.ListenAddress, handler))
}
