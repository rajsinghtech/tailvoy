package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

type EchoResponse struct {
	Path    string            `json:"path"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		resp := EchoResponse{
			Path:    r.URL.Path,
			Method:  r.Method,
			Headers: make(map[string]string),
		}
		for k, v := range r.Header {
			if len(v) > 0 {
				resp.Headers[k] = v[0]
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	fmt.Printf("backend listening on :%s\n", port)
	http.ListenAndServe(":"+port, nil)
}
