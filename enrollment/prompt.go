package enrollment

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// NormalizeEnrollmentCode accepts the human-friendly separators used by the
// control plane. It intentionally validates shape only; the server remains
// authoritative for the reviewed vocabulary and code hash.
func NormalizeEnrollmentCode(value string) (string, error) {
	if len(value) == 0 || len(value) > 256 {
		return "", fmt.Errorf("enrollment code is invalid")
	}
	parts := strings.FieldsFunc(strings.ToLower(strings.TrimSpace(value)), func(r rune) bool {
		return r == '-' || r == '_' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
	if len(parts) != 3 {
		return "", fmt.Errorf("enrollment code must contain three segments")
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 64 {
			return "", fmt.Errorf("enrollment code segment is invalid")
		}
		for _, character := range part {
			if character < 'a' || character > 'z' {
				return "", fmt.Errorf("enrollment code segment is invalid")
			}
		}
	}
	return strings.Join(parts, "-"), nil
}

func ReadEnrollmentCode(reader io.Reader, writer io.Writer) (string, error) {
	if reader == nil || writer == nil {
		return "", fmt.Errorf("enrollment code input is unavailable")
	}
	if _, err := fmt.Fprint(writer, "Enrollment code: "); err != nil {
		return "", fmt.Errorf("write enrollment code prompt: %w", err)
	}
	line, err := bufio.NewReader(io.LimitReader(reader, 257)).ReadString('\n')
	if err != nil && len(line) == 0 {
		if err == io.EOF {
			return "", fmt.Errorf("enrollment code input ended")
		}
		return "", fmt.Errorf("read enrollment code: %w", err)
	}
	code, err := NormalizeEnrollmentCode(line)
	if err != nil {
		return "", err
	}
	return code, nil
}
