package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"testing"
)

func TestAdmissionTLSConfiguration(t *testing.T) {
	config := &tls.Config{NextProtos: []string{"h2"}}
	hardenTLS(config)
	if config.MinVersion != tls.VersionTLS12 || len(config.NextProtos) != 1 || config.NextProtos[0] != "http/1.1" {
		t.Fatal("admission listener allows weak TLS or HTTP/2")
	}
}

func TestReadinessRequiresServingAndRejectsDraining(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serving := false
	check := servingCheck(ctx, func(*http.Request) error {
		if !serving {
			return errors.New("not listening")
		}
		return nil
	})
	if check(nil) == nil {
		t.Fatal("unavailable listener ready")
	}
	serving = true
	if err := check(nil); err != nil {
		t.Fatal(err)
	}
	cancel()
	if check(nil) == nil {
		t.Fatal("draining listener ready")
	}
}
