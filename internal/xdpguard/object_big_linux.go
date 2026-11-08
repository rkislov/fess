//go:build linux && (mips || mips64 || ppc64 || s390x)

package xdpguard

import _ "embed"

//go:embed filter-be.o
var object []byte
