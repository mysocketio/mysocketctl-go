package http

import (
	"fmt"
	"net"
	"net/http"
)

func StartLocalHTTPServer(dir string, l net.Listener) error {
	if dir == "" {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "hello to the built-in mysocket web server, it works!")
		})

		err := http.Serve(l, nil)

		if err != nil {
			return err
		}

		return nil
	}

	fs := http.FileServer(http.Dir(dir))
	http.Handle("/", http.StripPrefix("/", fs))

	err := http.Serve(l, nil)
	if err != nil {
		return err
	}

	return nil
}
