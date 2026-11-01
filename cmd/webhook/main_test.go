package main

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

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
