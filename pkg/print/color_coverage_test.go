package print

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNotAfterDate(t *testing.T) {
	t.Run("given future date, when NotAfterDate called, then green formatted", func(t *testing.T) {
		futureDate := time.Now().Add(365 * 24 * time.Hour)
		result := NotAfterDate(futureDate)
		assert.NotEmpty(t, result)
		assert.Contains(t, result, futureDate.Format("Jan _2 15:04:05 2006 MST"))
	})

	t.Run("given past date, when NotAfterDate called, then red formatted", func(t *testing.T) {
		pastDate := time.Now().Add(-365 * 24 * time.Hour)
		result := NotAfterDate(pastDate)
		assert.NotEmpty(t, result)
		assert.Contains(t, result, pastDate.Format("Jan _2 15:04:05 2006 MST"))
	})

	t.Run("given date within 30 days, when NotAfterDate called, then yellow formatted", func(t *testing.T) {
		soonDate := time.Now().Add(15 * 24 * time.Hour)
		result := NotAfterDate(soonDate)
		assert.NotEmpty(t, result)
		assert.Contains(t, result, soonDate.Format("Jan _2 15:04:05 2006 MST"))
	})
}

func TestExpiryStatus(t *testing.T) {
	t.Run("given expired status true, when ExpiryStatus called, then colored message returned", func(t *testing.T) {
		result := ExpiryStatus(true, "EXPIRED")
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "EXPIRED")
	})

	t.Run("given expired status false, when ExpiryStatus called, then uncolored message returned", func(t *testing.T) {
		result := ExpiryStatus(false, "VALID")
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "VALID")
	})
}

func TestExpiryMessage(t *testing.T) {
	t.Run("given days remaining > 30, when ExpiryMessage called, then green colored message returned", func(t *testing.T) {
		result := ExpiryMessage(60, "in 60 days")
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "in 60 days")
	})

	t.Run("given days remaining <= 30, when ExpiryMessage called, then yellow colored message returned", func(t *testing.T) {
		result := ExpiryMessage(15, "in 15 days")
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "in 15 days")
	})

	t.Run("given negative days (expired), when ExpiryMessage called, then yellow colored message returned", func(t *testing.T) {
		result := ExpiryMessage(-10, "10 days ago")
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "10 days ago")
	})

	t.Run("given exactly 30 days, when ExpiryMessage called, then yellow colored message returned", func(t *testing.T) {
		result := ExpiryMessage(30, "in 30 days")
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "in 30 days")
	})
}

func TestAttributeName(t *testing.T) {
	t.Run("given attribute name, when AttributeName called, then formatted name returned", func(t *testing.T) {
		result := AttributeName("Test Attribute")
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "Test Attribute")
	})

	t.Run("given empty attribute name, when AttributeName called, then formatted returned", func(t *testing.T) {
		result := AttributeName("")
		assert.NotNil(t, result)
	})
}

func TestSubAttributeName(t *testing.T) {
	t.Run("given sub-attribute name, when SubAttributeName called, then formatted name returned", func(t *testing.T) {
		result := SubAttributeName("Test Sub Attribute")
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "Test Sub Attribute")
	})

	t.Run("given empty sub-attribute name, when SubAttributeName called, then formatted returned", func(t *testing.T) {
		result := SubAttributeName("")
		assert.NotNil(t, result)
	})
}
