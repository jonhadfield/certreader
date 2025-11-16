package cert

import (
	"bytes"
	"errors"
	"fmt"
	"golang.design/x/clipboard"
	"io"
	"log/slog"
	"os"
)

type CSRLocations []CSRLocation

type CSRLocation struct {
	Path  string
	Error error
	CSRs  CSRs
}

func (c CSRLocation) Name() string {
	return c.Path
}

func LoadCSRsFromFile(fileName string) CSRLocation {
	b, err := os.ReadFile(fileName)
	if err != nil {
		slog.Error(fmt.Sprintf("load CSR from file %s: %v", fileName, err.Error()))
		return CSRLocation{Path: fileName, Error: err}
	}
	return loadCSR(fileName, b)
}

func LoadCSRFromStdin() CSRLocation {
	content, err := io.ReadAll(os.Stdin)
	if err != nil {
		slog.Error(fmt.Sprintf("load CSR from stdin: %v", err.Error()))
		return CSRLocation{Path: "stdin", Error: err}
	}
	return loadCSR("stdin", content)
}

func LoadCSRFromClipboard() CSRLocation {
	if err := clipboard.Init(); err != nil {
		slog.Error(fmt.Sprintf("load CSR from clipboard: %v", err.Error()))
		return CSRLocation{Path: "clipboard", Error: err}
	}

	content := clipboard.Read(clipboard.FmtText)
	if content == nil {
		return CSRLocation{Path: "clipboard", Error: errors.New("clipboard is empty")}
	}
	return loadCSR("clipboard", content)
}

func loadCSR(fileName string, data []byte) CSRLocation {
	trimmed := bytes.TrimSpace(data)
	csrs, err := FromCSRBytes(trimmed)
	if err != nil {
		slog.Error(fmt.Sprintf("parse CSR %s bytes: %v", fileName, err.Error()))
		return CSRLocation{Path: fileName, Error: err}
	}

	return CSRLocation{
		Path: fileName,
		CSRs: csrs,
	}
}
