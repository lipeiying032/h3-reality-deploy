//go:build windows

package main

import _ "embed"

//go:embed kernel/xray-h3-v9-win-amd64.exe
var kernelData []byte

const kernelFileName = "xray-h3-v9-win-amd64.exe"
