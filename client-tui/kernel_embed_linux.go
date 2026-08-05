//go:build linux

package main

import _ "embed"

//go:embed kernel/xray-h3-v9
var kernelData []byte

const kernelFileName = "xray-h3-v9"
