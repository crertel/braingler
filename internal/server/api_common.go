package server

import (
	"bytes"
	"encoding/json"
	"net/http"
)

// apiError is the response shape for any /api/v1 failure. It's deliberately
// boring — code is machine-readable, message is human-readable.
type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}

func writeAPIError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, apiError{Error: code, Message: message})
}

// encodeCompactJSON marshals v as one line of JSON — no pretty-printing,
// no trailing newline. Used by the SSE writer so each event fits in a
// single `data:` line.
func encodeCompactJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
