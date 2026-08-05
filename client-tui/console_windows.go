//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// setupConsole 将控制台代码页切换为 UTF-8 (65001) 并启用 ANSI VT 转义，
// 保证中文界面与彩色输出在 cmd / PowerShell 下正常显示。
func setupConsole() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	kernel32.NewProc("SetConsoleCP").Call(65001)
	kernel32.NewProc("SetConsoleOutputCP").Call(65001)

	const stdOutputHandle = ^uintptr(10) + 1 // -11: STD_OUTPUT_HANDLE
	hOut, _, _ := kernel32.NewProc("GetStdHandle").Call(stdOutputHandle)
	var mode uint32
	if hr, _, _ := kernel32.NewProc("GetConsoleMode").Call(hOut, uintptr(unsafe.Pointer(&mode))); hr != 0 {
		const enableVirtualTerminalProcessing = 0x0004
		_, _, _ = kernel32.NewProc("SetConsoleMode").Call(hOut, uintptr(mode|enableVirtualTerminalProcessing))
	}
	if title, err := syscall.UTF16PtrFromString("H3 REALITY Client"); err == nil {
		_, _, _ = kernel32.NewProc("SetConsoleTitleW").Call(uintptr(unsafe.Pointer(title)))
	}
}

// colorEnabled 仅在确认控制台支持 VT 转义时启用颜色。
func colorEnabled() bool {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	const stdOutputHandle = ^uintptr(10) + 1
	hOut, _, _ := kernel32.NewProc("GetStdHandle").Call(stdOutputHandle)
	var mode uint32
	hr, _, _ := kernel32.NewProc("GetConsoleMode").Call(hOut, uintptr(unsafe.Pointer(&mode)))
	return hr != 0 && mode&0x0004 != 0
}
