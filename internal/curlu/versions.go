package curlu

import (
	"runtime"
	"runtime/debug"
)

const (
	PinnedGoVersion   = "go1.24.0"
	PinnedUTLSVersion = "v1.8.2"
	pinnedUTLSModule  = "github.com/refraction-networking/utls"
)

func runtimeGoVersion() string {
	return runtime.Version()
}

func runtimeUTLSVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == pinnedUTLSModule {
			return dep.Version
		}
	}
	return "unknown"
}
