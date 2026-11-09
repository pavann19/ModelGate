package webhook

import (
	"net/http"
	"time"
)

// BoundedAdmissionHTTP limits work before controller-runtime decodes a body.
// The handler's independent verification semaphore still bounds registry work.
func BoundedAdmissionHTTP(next http.Handler) http.Handler {
	slots := make(chan struct{}, 32)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recover() != nil {
				// Panic values may contain credentials or workload text.
				http.Error(w, "admission handler failed", http.StatusInternalServerError)
			}
		}()
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "admission transport capacity exhausted", http.StatusServiceUnavailable)
			return
		}
		// The listener negotiates HTTP/1.1 so per-connection deadlines also
		// bound a slow body sender. These are refreshed on every request.
		controller := http.NewResponseController(w)
		_ = controller.SetReadDeadline(time.Now().Add(5 * time.Second))
		_ = controller.SetWriteDeadline(time.Now().Add(14 * time.Second))
		r.Body = http.MaxBytesReader(w, r.Body, 3*1024*1024)
		next.ServeHTTP(w, r)
	})
}
