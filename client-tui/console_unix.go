//go:build !windows

package main

import "os"

// setupConsole 在非 Windows 平台无需处理控制台代码页。
func setupConsole() {}

// colorEnabled 在终端为 TTY 且未设置 NO_COLOR 时启用 ANSI 颜色。
func colorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
