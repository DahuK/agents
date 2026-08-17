/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// ############################################################################
// #                                                                          #
// #   DELIBERATELY VULNERABLE TEST FIXTURE - DO NOT MERGE, DO NOT IMPORT     #
// #                                                                          #
// #   Every function below contains a known, intentional vulnerability. The  #
// #   sole purpose of this file is to verify that the security scanners       #
// #   configured in CI (CodeQL for Go, gosec via golangci-lint) actually      #
// #   fire on the classes of bug we care about.                               #
// #                                                                          #
// #   Two groups, and the difference between them is the point of the test:  #
// #                                                                          #
// #   Group A - taint originates from a REMOTE source (*http.Request).        #
// #     CodeQL's Go threat model only treats remote input as tainted, so      #
// #     these are the cases CodeQL is expected to report.                     #
// #                                                                          #
// #   Group B - taint originates from a LOCAL source (env vars, argv).        #
// #     gosec should still flag these, but CodeQL is expected to stay silent  #
// #     because `threat-models: local` is not supported for Go. If that       #
// #     prediction holds, it is empirical proof of the coverage gap and the   #
// #     reason gosec is enabled alongside CodeQL.                             #
// #                                                                          #
// ############################################################################

package vulnfixtures

import (
	"archive/zip"
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// ---------------------------------------------------------------------------
// Group A: remote taint source (*http.Request). CodeQL should report these.
// ---------------------------------------------------------------------------

// PathTraversal reads an attacker-controlled path straight off the query
// string. Expected: CodeQL go/path-injection (CWE-022).
func PathTraversal(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	data, err := os.ReadFile(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	_, _ = w.Write(data)
}

// CommandInjection passes request data to a shell.
// Expected: CodeQL go/command-injection (CWE-078), gosec G204.
func CommandInjection(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("host")
	out, err := exec.Command("sh", "-c", "ping -c 1 "+target).CombinedOutput()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(out)
}

// SSRF fetches a URL supplied by the caller.
// Expected: CodeQL go/request-forgery (CWE-918).
func SSRF(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("url")
	resp, err := http.Get(raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(w, resp.Body)
}

// SQLInjection concatenates request data into a query.
// Expected: CodeQL go/sql-injection (CWE-089).
func SQLInjection(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	rows, err := db.Query("SELECT name FROM sandboxes WHERE id = '" + id + "'")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer func() { _ = rows.Close() }()
	_, _ = fmt.Fprintln(w, "ok")
}

// ReflectedXSS echoes request data into an HTML response.
// Expected: CodeQL go/reflected-xss (CWE-079).
func ReflectedXSS(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	w.Header().Set("Content-Type", "text/html")
	_, _ = fmt.Fprintf(w, "<h1>hello %s</h1>", name)
}

// OpenRedirect redirects to a caller-supplied location.
// Expected: CodeQL go/open-url-redirect (CWE-601).
func OpenRedirect(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	http.Redirect(w, r, next, http.StatusFound)
}

// ZipSlip extracts an archive without validating entry names, so an entry
// called "../../etc/passwd" escapes the destination directory.
// Expected: CodeQL go/zipslip (CWE-022), gosec G305.
func ZipSlip(dest string, zr *zip.Reader) error {
	for _, f := range zr.File {
		out := filepath.Join(dest, f.Name) // no containment check
		rc, err := f.Open()
		if err != nil {
			return err
		}
		fh, err := os.Create(out)
		if err != nil {
			_ = rc.Close()
			return err
		}
		if _, err := io.Copy(fh, rc); err != nil {
			_ = rc.Close()
			_ = fh.Close()
			return err
		}
		_ = rc.Close()
		_ = fh.Close()
	}
	return nil
}

// CleartextLogging writes a credential taken from the request into the log.
// Expected: CodeQL go/clear-text-logging (CWE-312/315/359).
func CleartextLogging(r *http.Request) {
	password := r.URL.Query().Get("password")
	log.Printf("authenticating user with password=%s", password)
}

// IntegerOverflowConversion narrows an attacker-controlled int to int32.
// Expected: CodeQL go/incorrect-integer-conversion (CWE-190/681), gosec G115.
func IntegerOverflowConversion(r *http.Request) int32 {
	n, err := strconv.Atoi(r.URL.Query().Get("n"))
	if err != nil {
		return 0
	}
	return int32(n)
}

// DisabledCertificateCheck turns off TLS verification entirely.
// Expected: CodeQL go/disabled-certificate-check (CWE-295), gosec G402.
func DisabledCertificateCheck() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// WeakTLSVersion accepts TLS 1.0. This mirrors the real finding already
// present in pkg/traffic-extension/server/runserver.go.
// Expected: gosec G402.
func WeakTLSVersion() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS10}
}

// WeakHash uses MD5 to derive a token.
// Expected: CodeQL go/weak-crypto-algorithm (CWE-327/328), gosec G401.
func WeakHash(secret string) string {
	sum := md5.Sum([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Group B: local taint source. gosec should fire; CodeQL is expected NOT to,
// because the Go threat model covers remote sources only.
// ---------------------------------------------------------------------------

// LocalEnvCommandInjection builds a shell command from an environment
// variable. In a sandbox runtime this is the realistic shape of the bug: the
// untrusted value arrives via the container spec, not over HTTP.
// Expected: gosec G204. Expected NOT reported by CodeQL.
func LocalEnvCommandInjection() ([]byte, error) {
	image := os.Getenv("SANDBOX_IMAGE")
	return exec.Command("sh", "-c", "crictl pull "+image).CombinedOutput()
}

// LocalArgvPathTraversal opens a path taken from argv.
// Expected: gosec G304. Expected NOT reported by CodeQL.
func LocalArgvPathTraversal() ([]byte, error) {
	if len(os.Args) < 2 {
		return nil, nil
	}
	return os.ReadFile(os.Args[1])
}

// WorldWritableStateDir creates a directory every local user can write to,
// which is a classic sandbox-escape stepping stone.
// Expected: gosec G301. Expected NOT reported by CodeQL (no query for CWE-732
// in the Go suite at all).
func WorldWritableStateDir(dir string) error {
	err := os.MkdirAll(dir, 0777)
	return err
}

// WorldWritableSecretFile writes credentials with permissive file modes.
// Expected: gosec G306.
func WorldWritableSecretFile(path, token string) error {
	return os.WriteFile(path, []byte(token), 0666)
}

// HardcodedCredential embeds a static secret in the binary.
// Expected: gosec G101.
func HardcodedCredential() string {
	apiKey := "AKIAIOSFODNN7EXAMPLE0000"
	return apiKey
}

// PredictableSandboxID uses a non-cryptographic RNG for a value that gates
// access, so IDs are guessable across processes.
// Expected: gosec G404.
func PredictableSandboxID() string {
	return fmt.Sprintf("sbx-%d", rand.Int63())
}
