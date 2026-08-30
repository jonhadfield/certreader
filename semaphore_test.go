package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// peakConcurrency runs work through a semaphore and reports the most that were
// ever running at once, which is the only thing worth asserting about a cap.
func peakConcurrency(limit, workers int) int64 {

	slots := newSemaphore(limit)
	var running, peak atomic.Int64

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slots.acquire()
			defer slots.release()

			current := running.Add(1)
			for {
				highest := peak.Load()
				if current <= highest || peak.CompareAndSwap(highest, current) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			running.Add(-1)
		}()
	}
	wg.Wait()
	return peak.Load()
}

func TestSemaphore(t *testing.T) {

	t.Run("given a limit then no more than that run at once", func(t *testing.T) {
		assert.LessOrEqual(t, peakConcurrency(4, 50), int64(4))
	})

	t.Run("given a limit of one then the work is serialised", func(t *testing.T) {
		assert.Equal(t, int64(1), peakConcurrency(1, 20))
	})

	t.Run("given no limit then the work is not held back", func(t *testing.T) {
		// zero means unbounded, so this should reach well past any small cap
		assert.Greater(t, peakConcurrency(0, 50), int64(4))
	})

	t.Run("given a negative limit then it is treated as no limit", func(t *testing.T) {
		assert.Nil(t, newSemaphore(-1))
		assert.Nil(t, newSemaphore(0))
	})

	t.Run("given no limit then acquire and release do nothing", func(t *testing.T) {
		// a nil semaphore must not block or panic
		var none semaphore
		assert.NotPanics(t, func() {
			none.acquire()
			none.release()
		})
	})

	t.Run("given every worker finishes then no slot is left held", func(t *testing.T) {
		slots := newSemaphore(2)
		for i := 0; i < 10; i++ {
			slots.acquire()
			slots.release()
		}
		// if release leaked, this would block rather than return
		assert.NotPanics(t, func() {
			slots.acquire()
			slots.release()
		})
	})
}
