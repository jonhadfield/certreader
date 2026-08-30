package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jonhadfield/certreader/pkg/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShouldReadStdin(t *testing.T) {
	tests := []struct {
		name  string
		flags Flags
		piped bool
		want  bool
	}{
		{
			name:  "a pipe and nothing else named is the one case stdin is read",
			piped: true,
			want:  true,
		},
		{
			name:  "a terminal is never read, since there is nothing to read",
			piped: false,
		},
		{
			name:  "a file was named, so the pipe is not the input",
			flags: Flags{Args: []string{"cert.pem"}},
			piped: true,
		},
		{
			name:  "a host was named, so the pipe is not the input",
			flags: Flags{Args: []string{"example.com:443"}},
			piped: true,
		},
		{
			name:  "the clipboard was asked for, so the pipe is not the input",
			flags: Flags{Clipboard: true},
			piped: true,
		},
		{
			name:  "no pipe and no arguments leaves nothing to read",
			piped: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, shouldReadStdin(test.flags, test.piped))
		})
	}
}

func TestLoadLocationsDoesNotWaitOnAnIdlePipe(t *testing.T) {
	// A parent process can hand over a pipe on stdin and never write to it.
	// Reading it then blocks until that process exits, however long that is,
	// with a file already named on the command line and ready to read.
	t.Run("given a file argument and a pipe nothing is written to, then the file is read without waiting", func(t *testing.T) {
		reader, writer, err := os.Pipe()
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = writer.Close()
			_ = reader.Close()
		})

		original := os.Stdin
		os.Stdin = reader
		t.Cleanup(func() { os.Stdin = original })

		certPath := filepath.Join(t.TempDir(), "test.pem")
		require.NoError(t, os.WriteFile(certPath, createTestCertificatePEM(t, "Test Certificate"), 0o600))

		loaded := make(chan cert.Locations, 1)
		go func() { loaded <- LoadLocations(Flags{Args: []string{certPath}}) }()

		select {
		case locations := <-loaded:
			require.Len(t, locations, 1)
			assert.Equal(t, certPath, locations[0].Path)
			assert.Nil(t, locations[0].Error)
		case <-time.After(10 * time.Second):
			t.Fatal("LoadLocations blocked reading stdin although a file was given to read")
		}
	})
}
