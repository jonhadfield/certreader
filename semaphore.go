package main

// semaphore bounds how many goroutines may be doing the bounded work at once.
// A limit of zero or less means no bound, which is what a nil channel gives:
// the acquire and release below are then no-ops.
type semaphore chan struct{}

func newSemaphore(limit int) semaphore {
	if limit <= 0 {
		return nil
	}
	return make(semaphore, limit)
}

func (s semaphore) acquire() {
	if s == nil {
		return
	}
	s <- struct{}{}
}

func (s semaphore) release() {
	if s == nil {
		return
	}
	<-s
}
