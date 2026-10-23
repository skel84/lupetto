package explorer

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// productsLoad is the outcome of the last `lupetto products list`, shown on
// the Vulnerabilities pages, logged when it changes, and exported as
// lupetto_products_load_success.
type productsLoad struct {
	mu  sync.Mutex
	at  time.Time
	err string
}

// listProducts runs `lupetto products list` and records the outcome. A call
// cancelled by its caller (a closed request or shutdown) records nothing.
func (s *Server) listProducts(ctx context.Context) (*ProductsDocument, error) {
	document, err := s.cli.Products(ctx, s.config.Products, "list", "", nil)
	if err != nil && errors.Is(ctx.Err(), context.Canceled) {
		return nil, err
	}
	text := ""
	if err != nil {
		text = err.Error()
	}
	load := &s.productsLoad
	load.mu.Lock()
	first, previous := load.at.IsZero(), load.err
	load.at, load.err = time.Now(), text
	load.mu.Unlock()
	switch {
	case text != "" && text != previous:
		s.logf("products file %s could not be read: %s", s.config.Products, text)
	case text == "" && previous != "" && !first:
		s.logf("products file %s can be read again", s.config.Products)
	}
	return document, err
}

// productsLoadState returns the time and error of the last recorded load;
// a zero time means none has completed.
func (s *Server) productsLoadState() (time.Time, string) {
	s.productsLoad.mu.Lock()
	defer s.productsLoad.mu.Unlock()
	return s.productsLoad.at, s.productsLoad.err
}

func (s *Server) logf(format string, args ...any) {
	if s.config.Log != nil {
		_, _ = fmt.Fprintf(s.config.Log, format+"\n", args...)
	}
}
