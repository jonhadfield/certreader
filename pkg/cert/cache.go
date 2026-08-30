package cert

import "sync"

// singleFlightCache fetches a value once per key however many callers ask at
// the same time. A plain map would not do: the revocation checks run
// concurrently, so every goroutine would miss together and every one would
// fetch the same file.
type singleFlightCache[T any] struct {
	mu      sync.Mutex
	entries map[string]*cacheEntry[T]
}

type cacheEntry[T any] struct {
	// ready is closed once the value is settled, which is what late callers
	// wait on rather than fetching again
	ready chan struct{}
	value T
	err   error
}

// get returns the cached value for the key, calling fetch only if no one else
// already is. A failure is not remembered, so a later caller is free to try
// again; callers already waiting on the failed attempt share its error.
func (c *singleFlightCache[T]) get(key string, fetch func() (T, error)) (T, error) {

	c.mu.Lock()
	if c.entries == nil {
		c.entries = map[string]*cacheEntry[T]{}
	}
	if entry, waiting := c.entries[key]; waiting {
		c.mu.Unlock()
		<-entry.ready
		return entry.value, entry.err
	}
	entry := &cacheEntry[T]{ready: make(chan struct{})}
	c.entries[key] = entry
	c.mu.Unlock()

	entry.value, entry.err = fetch()
	close(entry.ready)

	if entry.err != nil {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
	}
	return entry.value, entry.err
}

// len reports how many keys are held, for tests.
func (c *singleFlightCache[T]) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.entries)
}
