package manager

import (
	"os"
	"reflect"
	"testing"
	"unsafe"
)

func TestOpenExecutableForUprobeFallsBackForNonELFWithExplicitAddress(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "non-elf-*")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer tmp.Close()

	if _, err := tmp.WriteString("PK\x03\x04not-an-elf"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}

	ex, err := openExecutableForUprobe(tmp.Name(), 0x1234)
	if err != nil {
		t.Fatalf("openExecutableForUprobe() error = %v", err)
	}

	if got := readExecutableField[string](t, ex, "path"); got != tmp.Name() {
		t.Fatalf("path = %q, want %q", got, tmp.Name())
	}

	if got := readExecutableField[map[string]uint64](t, ex, "cachedAddresses"); got == nil {
		t.Fatalf("cachedAddresses should be initialized")
	}
}

func TestOpenExecutableForUprobeKeepsErrorWithoutExplicitAddress(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "non-elf-*")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer tmp.Close()

	if _, err := tmp.WriteString("PK\x03\x04not-an-elf"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}

	if _, err := openExecutableForUprobe(tmp.Name(), 0); err == nil {
		t.Fatalf("openExecutableForUprobe() error = nil, want non-nil")
	}
}

func readExecutableField[T any](t *testing.T, ex any, fieldName string) T {
	t.Helper()

	field := reflect.ValueOf(ex).Elem().FieldByName(fieldName)
	if !field.IsValid() {
		t.Fatalf("field %q not found", fieldName)
	}

	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface().(T)
}
