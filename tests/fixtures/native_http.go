// Standalone fixture for a target with no Python or TLS command-line tools.
package main

import (
	"flag"
	"net/http"
)

func main() {
	address := flag.String("bind", "127.0.0.1:3000", "HTTP listen address")
	flag.Parse()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Reap-native-fixture")
		_, _ = w.Write([]byte("<html><title>Python-free lab application</title></html>"))
	})
	if err := http.ListenAndServe(*address, nil); err != nil {
		panic(err)
	}
}
