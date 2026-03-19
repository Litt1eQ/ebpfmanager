package manager

import (
	"fmt"
	"reflect"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf/link"
)

// openExecutableForUprobe preserves the normal ELF validation path for regular
// binaries, but falls back to a path-only executable when the caller already
// provides an explicit uprobe address. This is required for Android apps whose
// native libraries are mapped directly from container files like APKs.
func openExecutableForUprobe(path string, address uint64) (*link.Executable, error) {
	ex, err := link.OpenExecutable(path)
	if err == nil || address == 0 {
		return ex, err
	}

	if !canBypassExecutableValidation(err) {
		return nil, err
	}

	return newExecutableForExplicitAddress(path), nil
}

func canBypassExecutableValidation(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "parse ELF file") ||
		strings.Contains(msg, "not an executable or a shared object")
}

func newExecutableForExplicitAddress(path string) *link.Executable {
	ex := &link.Executable{}
	setExecutableField(ex, "path", path)
	setExecutableField(ex, "cachedAddresses", make(map[string]uint64))
	return ex
}

func setExecutableField(ex *link.Executable, fieldName string, value any) {
	field := reflect.ValueOf(ex).Elem().FieldByName(fieldName)
	if !field.IsValid() {
		panic(fmt.Sprintf("link.Executable field %q not found", fieldName))
	}

	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(value))
}
