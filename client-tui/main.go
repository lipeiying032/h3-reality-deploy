// H3 REALITY Client — 单文件 TUI 客户端外壳
//
// 职责：TUI 交互界面 + VLESS 配置管理 + fork 内核进程管理。
// 内核（xray-h3-v9）与绕过大陆规则集（geosite.dat / geoip.dat）通过 go:embed
// 打进同一个可执行文件，运行时释放到临时目录后作为子进程启动。
package main

import (
	"bufio"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed assets/geosite.dat assets/geoip.dat
var assetFS embed.FS

const (
	version     = "1.0"
	socksPort   = 10808
	httpPort    = 10809
	configFile  = "configs.json"
	currentFile = "current.json"
	lockFile    = "configs.lock"
	boxWidth    = 54
)

var (
	uuidRe  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	colorOn = true
	km      kernelManager
)

// ---------------- ANSI 颜色 ----------------

const (
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
	ansiReset  = "\x1b[0m"
)

func paint(s, code string) string {
	if !colorOn {
		return s
	}
	return code + s + ansiReset
}

func red(s string) string    { return paint(s, ansiRed) }
func green(s string) string  { return paint(s, ansiGreen) }
func yellow(s string) string { return paint(s, ansiYellow) }
func cyan(s string) string   { return paint(s, ansiCyan) }

// ---------------- 终端宽度辅助（CJK 按 2 列） ----------------

func isWideRune(r rune) bool {
	switch {
	case r >= 0x1100 && r <= 0x115F, // Hangul Jamo
		r >= 0x2E80 && r <= 0x303E, // CJK 部首 / 符号
		r >= 0x3041 && r <= 0x33FF, // 假名 / CJK 兼容
		r >= 0x3400 && r <= 0x4DBF, // CJK 扩展 A
		r >= 0x4E00 && r <= 0x9FFF, // CJK 统一表意
		r >= 0xA000 && r <= 0xA4CF, // 彝文
		r >= 0xAC00 && r <= 0xD7A3, // 谚文音节
		r >= 0xF900 && r <= 0xFAFF, // CJK 兼容表意
		r >= 0xFE30 && r <= 0xFE4F, // CJK 兼容形式
		r >= 0xFF00 && r <= 0xFF60, // 全角形式
		r >= 0xFFE0 && r <= 0xFFE6, // 全角符号
		r >= 0x20000 && r <= 0x3FFFD:
		return true
	}
	return false
}

func dispWidth(s string) int {
	w := 0
	for _, r := range s {
		if isWideRune(r) {
			w += 2
		} else {
			w++
		}
	}
	return w
}

func truncateWidth(s string, max int) string {
	w := 0
	var b strings.Builder
	for _, r := range s {
		rw := 1
		if isWideRune(r) {
			rw = 2
		}
		if w+rw > max {
			b.WriteRune('…')
			break
		}
		b.WriteRune(r)
		w += rw
	}
	return b.String()
}

func padTo(s string, w int) string {
	if gap := w - dispWidth(s); gap > 0 {
		return s + strings.Repeat(" ", gap)
	}
	return s
}

func boxLine(text string, width int) string {
	return "║  " + padTo(truncateWidth(text, width-4), width-4) + "║"
}

// ---------------- VLESS 链接解析 ----------------

// VlessConfig 是解析后的节点配置（configs.json 数组元素）。
type VlessConfig struct {
	Name      string `json:"name"`
	UUID      string `json:"uuid"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Path      string `json:"path"`
	SNI       string `json:"sni"`
	FP        string `json:"fp"`
	PBK       string `json:"pbk"`
	SID       string `json:"sid"`
	ALPN      string `json:"alpn"`
	Mode      string `json:"mode"`
	HostParam string `json:"host_param,omitempty"`
	Remark    string `json:"remark"`
	Link      string `json:"link"`
	CreatedAt string `json:"created_at,omitempty"`
}

func parseVless(raw string) (*VlessConfig, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, errors.New("链接为空")
	}
	if !strings.HasPrefix(s, "vless://") {
		return nil, errors.New("不是 vless:// 分享链接")
	}
	rest := strings.TrimPrefix(s, "vless://")

	remark := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		remark = rest[i+1:]
		rest = rest[:i]
		if dec, err := url.PathUnescape(remark); err == nil {
			remark = dec
		}
	}
	remark = strings.TrimSpace(remark)

	queryStr := ""
	if i := strings.Index(rest, "?"); i >= 0 {
		queryStr = rest[i+1:]
		rest = rest[:i]
	}

	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return nil, errors.New("缺少 @ 分隔符，格式应为 vless://UUID@主机:端口?参数#备注")
	}
	uuidStr := strings.TrimSpace(rest[:at])
	hostPort := rest[at+1:]
	if !uuidRe.MatchString(uuidStr) {
		return nil, errors.New("UUID 格式不正确: " + uuidStr)
	}
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, errors.New("主机:端口 格式不正确: " + hostPort)
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return nil, errors.New("主机地址为空")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("端口不正确: " + portStr)
	}

	q, err := url.ParseQuery(queryStr)
	if err != nil {
		return nil, errors.New("参数解析失败: " + err.Error())
	}
	get := func(k string) string { return strings.TrimSpace(q.Get(k)) }

	if enc := get("encryption"); enc != "" && enc != "none" {
		return nil, errors.New("仅支持 encryption=none，当前值: " + enc)
	}
	if get("security") != "reality" {
		return nil, errors.New("仅支持 REALITY 安全协议（链接需含 security=reality）")
	}
	if get("type") != "xhttp" {
		return nil, errors.New("仅支持 xhttp 传输（链接需含 type=xhttp）")
	}

	sni := get("sni")
	pbk := get("pbk")
	if sni == "" || pbk == "" {
		return nil, errors.New("缺少 sni 或 pbk（REALITY 必需参数）")
	}

	path := get("path")
	if path == "" {
		path = "/"
	}
	fp := get("fp")
	if fp == "" {
		fp = "chrome"
	}
	alpn := get("alpn")
	if alpn == "" {
		alpn = "h3"
	}
	mode := get("mode")
	if mode == "" {
		mode = "stream-one"
	}

	name := remark
	if name == "" {
		name = fmt.Sprintf("%s:%d", host, port)
	}

	return &VlessConfig{
		Name:      name,
		UUID:      uuidStr,
		Host:      host,
		Port:      port,
		Path:      path,
		SNI:       sni,
		FP:        fp,
		PBK:       pbk,
		SID:       get("sid"),
		ALPN:      alpn,
		Mode:      mode,
		HostParam: get("host"),
		Remark:    remark,
		Link:      s,
	}, nil
}

func printCfgSummary(c *VlessConfig) {
	fmt.Printf("  名称     : %s\n", c.Name)
	fmt.Printf("  UUID     : %s\n", c.UUID)
	fmt.Printf("  服务器   : %s:%d\n", c.Host, c.Port)
	fmt.Printf("  传输     : xhttp (%s)\n", c.Mode)
	fmt.Printf("  安全     : REALITY\n")
	fmt.Printf("  SNI      : %s\n", c.SNI)
	fmt.Printf("  指纹     : %s\n", c.FP)
	fmt.Printf("  PublicKey: %s\n", c.PBK)
	fmt.Printf("  ShortId  : %s\n", c.SID)
	fmt.Printf("  Path     : %s\n", c.Path)
	fmt.Printf("  ALPN     : %s\n", c.ALPN)
	if c.Remark != "" {
		fmt.Printf("  备注     : %s\n", c.Remark)
	}
}

// ---------------- 配置存储（程序目录 configs.json / current.json / 锁文件） ----------------

func programDir() string {
	if exe, err := os.Executable(); err == nil {
		if d := filepath.Dir(exe); d != "" {
			return d
		}
	}
	d, _ := os.Getwd()
	return d
}

func acquireLock(dir string) (func(), error) {
	path := filepath.Join(dir, lockFile)
	for i := 0; i < 60; i++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			fmt.Fprintf(f, "%d\n", os.Getpid())
			f.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		if fi, serr := os.Stat(path); serr == nil && time.Since(fi.ModTime()) > 30*time.Second {
			// 疑似上次异常退出留下的过期锁，清掉重试
			_ = os.Remove(path)
			continue
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, errors.New("配置文件正被其他进程占用（" + lockFile + "），请稍后再试")
}

func withConfigLock(fn func() error) error {
	unlock, err := acquireLock(programDir())
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

func loadConfigs() ([]VlessConfig, error) {
	data, err := os.ReadFile(filepath.Join(programDir(), configFile))
	if os.IsNotExist(err) {
		return []VlessConfig{}, nil
	}
	if err != nil {
		return nil, err
	}
	var cfgs []VlessConfig
	if err := json.Unmarshal(data, &cfgs); err != nil {
		return nil, errors.New(configFile + " 解析失败: " + err.Error())
	}
	return cfgs, nil
}

// writeConfigs 仅在已持锁时调用。
func writeConfigs(cfgs []VlessConfig) error {
	data, err := json.MarshalIndent(cfgs, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(programDir(), configFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func currentName() string {
	data, err := os.ReadFile(filepath.Join(programDir(), currentFile))
	if err != nil {
		return ""
	}
	var m struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(data, &m) != nil || m.Name == "" {
		return ""
	}
	return m.Name
}

// writeCurrent 仅在已持锁时调用。
func writeCurrent(name string) error {
	data, err := json.MarshalIndent(map[string]string{"name": name}, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(programDir(), currentFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func addConfig(cfg *VlessConfig) error {
	return withConfigLock(func() error {
		cfgs, err := loadConfigs()
		if err != nil {
			return err
		}
		for _, c := range cfgs {
			if c.Name == cfg.Name {
				return fmt.Errorf("已存在同名配置: %s", cfg.Name)
			}
		}
		cfg.CreatedAt = time.Now().Format("2006-01-02 15:04:05")
		cfgs = append(cfgs, *cfg)
		if err := writeConfigs(cfgs); err != nil {
			return err
		}
		if len(cfgs) == 1 {
			// 第一个配置自动设为当前
			_ = writeCurrent(cfg.Name)
		}
		return nil
	})
}

func removeConfig(name string) error {
	return withConfigLock(func() error {
		cfgs, err := loadConfigs()
		if err != nil {
			return err
		}
		out := cfgs[:0]
		found := false
		for _, c := range cfgs {
			if c.Name == name {
				found = true
				continue
			}
			out = append(out, c)
		}
		if !found {
			return errors.New("未找到配置: " + name)
		}
		if err := writeConfigs(out); err != nil {
			return err
		}
		if currentName() == name {
			_ = writeCurrent("")
		}
		return nil
	})
}

func renameConfig(oldName, newName string) error {
	if strings.TrimSpace(newName) == "" {
		return errors.New("新名称不能为空")
	}
	return withConfigLock(func() error {
		cfgs, err := loadConfigs()
		if err != nil {
			return err
		}
		found := false
		for i := range cfgs {
			if cfgs[i].Name == newName {
				return fmt.Errorf("已存在同名配置: %s", newName)
			}
			if cfgs[i].Name == oldName {
				cfgs[i].Name = newName
				found = true
			}
		}
		if !found {
			return errors.New("未找到配置: " + oldName)
		}
		if err := writeConfigs(cfgs); err != nil {
			return err
		}
		if currentName() == oldName {
			_ = writeCurrent(newName)
		}
		return nil
	})
}

// ---------------- 生成内核客户端配置 ----------------

type xrayLog struct {
	LogLevel string `json:"loglevel"`
}

type inbound struct {
	Tag      string `json:"tag"`
	Listen   string `json:"listen"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type xrayUser struct {
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
	Flow       string `json:"flow"`
}

type vnext struct {
	Address string     `json:"address"`
	Port    int        `json:"port"`
	Users   []xrayUser `json:"users"`
}

type vlessSettings struct {
	Vnext []vnext `json:"vnext"`
}

type quicParams struct {
	Congestion                  string `json:"congestion"`
	BBRProfile                  string `json:"bbrProfile"`
	InitStreamReceiveWindow     int    `json:"initStreamReceiveWindow"`
	MaxStreamReceiveWindow      int    `json:"maxStreamReceiveWindow"`
	InitConnectionReceiveWindow int    `json:"initConnectionReceiveWindow"`
	MaxConnectionReceiveWindow  int    `json:"maxConnectionReceiveWindow"`
	MaxIdleTimeout              int    `json:"maxIdleTimeout"`
	KeepAlivePeriod             int    `json:"keepAlivePeriod"`
	MaxIncomingStreams          int    `json:"maxIncomingStreams"`
}

type finalmask struct {
	QuicParams quicParams `json:"quicParams"`
}

type xhttpSettings struct {
	Mode              string            `json:"mode"`
	EnableH3          bool              `json:"enableH3"`
	Path              string            `json:"path"`
	NoGRPCHeader      bool              `json:"noGRPCHeader"`
	Headers           map[string]string `json:"headers"`
	XPaddingBytes     string            `json:"xPaddingBytes"`
	XPaddingObfsMode  bool              `json:"xPaddingObfsMode"`
	XPaddingPlacement string            `json:"xPaddingPlacement"`
	XPaddingKey       string            `json:"xPaddingKey"`
	XPaddingMethod    string            `json:"xPaddingMethod"`
}

type realitySettings struct {
	ServerName  string   `json:"serverName"`
	Fingerprint string   `json:"fingerprint"`
	PublicKey   string   `json:"publicKey"`
	ShortID     string   `json:"shortId"`
	Alpn        []string `json:"alpn"`
}

type streamSettings struct {
	Network         string           `json:"network"`
	Security        string           `json:"security"`
	Finalmask       *finalmask       `json:"finalmask"`
	XHTTPSettings   *xhttpSettings   `json:"xhttpSettings"`
	RealitySettings *realitySettings `json:"realitySettings"`
}

type outbound struct {
	Tag            string `json:"tag"`
	Protocol       string `json:"protocol"`
	Settings       any    `json:"settings,omitempty"`
	StreamSettings any    `json:"streamSettings,omitempty"`
}

type routingRule struct {
	Type        string   `json:"type"`
	Domain      []string `json:"domain,omitempty"`
	IP          []string `json:"ip,omitempty"`
	Network     string   `json:"network,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

type routing struct {
	DomainStrategy string        `json:"domainStrategy"`
	Rules          []routingRule `json:"rules"`
}

type xrayConfig struct {
	Log       xrayLog    `json:"log"`
	Inbounds  []inbound  `json:"inbounds"`
	Outbounds []outbound `json:"outbounds"`
	Routing   routing    `json:"routing"`
}

// buildXrayConfig 按 v2rayN「绕过大陆」模式生成内核配置：
// geosite:cn / geoip:cn 直连，geosite:geolocation-!cn 走代理，其余 tcp/udp 兜底代理。
func buildXrayConfig(c *VlessConfig) ([]byte, error) {
	alpnList := []string{"h3"}
	if c.ALPN != "" {
		alpnList = nil
		for _, p := range strings.Split(c.ALPN, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				alpnList = append(alpnList, p)
			}
		}
	}
	mode := c.Mode
	if mode == "" {
		mode = "stream-one"
	}
	fp := c.FP
	if fp == "" {
		fp = "chrome"
	}

	cfg := xrayConfig{
		Log: xrayLog{LogLevel: "warning"},
		Inbounds: []inbound{
			{Tag: "socks-in", Listen: "127.0.0.1", Port: socksPort, Protocol: "socks"},
			{Tag: "http-in", Listen: "127.0.0.1", Port: httpPort, Protocol: "http"},
		},
		Outbounds: []outbound{
			{
				Tag:      "proxy",
				Protocol: "vless",
				Settings: vlessSettings{
					Vnext: []vnext{{
						Address: c.Host,
						Port:    c.Port,
						Users:   []xrayUser{{ID: c.UUID, Encryption: "none", Flow: ""}},
					}},
				},
				StreamSettings: &streamSettings{
					Network:  "xhttp",
					Security: "reality",
					Finalmask: &finalmask{
						QuicParams: quicParams{
							Congestion:                  "bbr",
							BBRProfile:                  "aggressive",
							InitStreamReceiveWindow:     4194304,
							MaxStreamReceiveWindow:      16777216,
							InitConnectionReceiveWindow: 8388608,
							MaxConnectionReceiveWindow:  67108864,
							MaxIdleTimeout:              60,
							KeepAlivePeriod:             30,
							MaxIncomingStreams:          1000,
						},
					},
					XHTTPSettings: &xhttpSettings{
						Mode:         mode,
						EnableH3:     true,
						Path:         c.Path,
						NoGRPCHeader: true,
						Headers: map[string]string{
							"accept-encoding": "gzip, deflate, br, zstd",
							"content-type":    "application/octet-stream",
							"dnt":             "",
						},
						XPaddingBytes:     "32-96",
						XPaddingObfsMode:  true,
						XPaddingPlacement: "query",
						XPaddingKey:       "cb",
						XPaddingMethod:    "tokenish",
					},
					RealitySettings: &realitySettings{
						ServerName:  c.SNI,
						Fingerprint: fp,
						PublicKey:   c.PBK,
						ShortID:     c.SID,
						Alpn:        alpnList,
					},
				},
			},
			{Tag: "direct", Protocol: "freedom"},
			{Tag: "block", Protocol: "blackhole"},
		},
		Routing: routing{
			DomainStrategy: "IPIfNonMatch",
			Rules: []routingRule{
				{Type: "field", Domain: []string{"geosite:cn"}, OutboundTag: "direct"},
				{Type: "field", IP: []string{"geoip:cn"}, OutboundTag: "direct"},
				{Type: "field", Domain: []string{"geosite:geolocation-!cn"}, OutboundTag: "proxy"},
				{Type: "field", Network: "tcp,udp", OutboundTag: "proxy"},
			},
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// ---------------- 内核进程管理 ----------------

type kernelManager struct {
	mu      sync.Mutex
	proc    *os.Process
	cmd     *exec.Cmd
	dir     string
	logFile *os.File
	exitCh  chan struct{}
	logTail []string
}

func (km *kernelManager) runningPID() (int, bool) {
	km.mu.Lock()
	defer km.mu.Unlock()
	if km.proc != nil {
		return km.proc.Pid, true
	}
	return 0, false
}

func (km *kernelManager) tailLog() []string {
	km.mu.Lock()
	defer km.mu.Unlock()
	return append([]string(nil), km.logTail...)
}

func (km *kernelManager) scanLines(r io.Reader, logFile *os.File) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		km.mu.Lock()
		km.logTail = append(km.logTail, line)
		if len(km.logTail) > 40 {
			km.logTail = km.logTail[len(km.logTail)-40:]
		}
		km.mu.Unlock()
		fmt.Printf(" [Core] %s\n", line)
		if logFile != nil {
			fmt.Fprintln(logFile, line)
		}
	}
}

// start 释放内嵌内核与规则文件、生成配置并启动内核子进程。
func (km *kernelManager) start(c *VlessConfig) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.proc != nil {
		return errors.New("代理已在运行")
	}
	if len(kernelData) == 0 {
		return errors.New("内嵌内核资源缺失（请检查构建时的 kernel/ 目录）")
	}
	if err := checkPortFree(socksPort); err != nil {
		return fmt.Errorf("端口 %d 已被其他程序占用: %v", socksPort, err)
	}
	if err := checkPortFree(httpPort); err != nil {
		return fmt.Errorf("端口 %d 已被其他程序占用: %v", httpPort, err)
	}

	dir, err := os.MkdirTemp("", "h3-client-*")
	if err != nil {
		return err
	}

	kernelPath := filepath.Join(dir, kernelFileName)
	if err := os.WriteFile(kernelPath, kernelData, 0o755); err != nil {
		_ = os.RemoveAll(dir)
		return err
	}
	for _, name := range []string{"geosite.dat", "geoip.dat"} {
		data, err := assetFS.ReadFile("assets/" + name)
		if err != nil {
			_ = os.RemoveAll(dir)
			return fmt.Errorf("规则文件 %s 缺失: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			_ = os.RemoveAll(dir)
			return err
		}
	}
	cfgJSON, err := buildXrayConfig(c)
	if err != nil {
		_ = os.RemoveAll(dir)
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), cfgJSON, 0o644); err != nil {
		_ = os.RemoveAll(dir)
		return err
	}

	logsDir := filepath.Join(programDir(), "logs")
	_ = os.MkdirAll(logsDir, 0o755)
	logFile, err := os.OpenFile(
		filepath.Join(logsDir, "run-"+time.Now().Format("20060102-150405")+".log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		logFile = nil // 日志目录不可写时仅实时输出
	}

	cmd := exec.Command(kernelPath, "run", "-c", "config.json")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+dir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = os.RemoveAll(dir)
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = os.RemoveAll(dir)
		return err
	}

	km.dir = dir
	km.logFile = logFile
	km.logTail = nil
	km.cmd = cmd

	if err := cmd.Start(); err != nil {
		km.proc = nil
		km.cleanupLocked()
		return err
	}
	km.proc = cmd.Process

	// 注意：wait/日志 goroutine 必须在 Start 之后创建，
	// 否则存在 cmd.Wait() 先于 Start 执行的竞态（返回 "exec: not started"）。
	exitCh := make(chan struct{})
	km.exitCh = exitCh
	go km.scanLines(stdout, logFile)
	go km.scanLines(stderr, logFile)
	go func() {
		werr := cmd.Wait()
		code := "0"
		detail := ""
		if werr != nil {
			code = "?"
			if ee, ok := werr.(*exec.ExitError); ok {
				code = strconv.Itoa(ee.ExitCode())
				detail = ee.Error()
			} else {
				detail = werr.Error()
			}
		}
		km.mu.Lock()
		km.proc = nil
		km.cmd = nil
		km.cleanupLocked() // 进程已退出：释放临时目录与日志文件（幂等）
		km.mu.Unlock()
		close(exitCh)
		if detail != "" {
			fmt.Printf("  [内核] 代理进程已退出 (code: %s, %s)\n", code, detail)
		} else {
			fmt.Printf("  [内核] 代理进程已退出 (code: %s)\n", code)
		}
	}()

	if !waitPort(socksPort, 5*time.Second) {
		select {
		case <-exitCh:
		default:
			// 进程仍在但端口未就绪，强制结束
			_ = cmd.Process.Kill()
			select {
			case <-exitCh:
			case <-time.After(5 * time.Second):
			}
		}
		tail := km.tailLog()
		km.cleanupLocked()
		msg := "内核启动失败，端口未就绪"
		if len(tail) > 0 {
			msg += "，最后日志:\n"
			for _, l := range tail {
				msg += "    " + l + "\n"
			}
		}
		return errors.New(strings.TrimSuffix(msg, "\n"))
	}
	return nil
}

func (km *kernelManager) cleanupLocked() {
	if km.logFile != nil {
		_ = km.logFile.Close()
		km.logFile = nil
	}
	if km.dir != "" {
		_ = os.RemoveAll(km.dir)
		km.dir = ""
	}
	km.cmd = nil
	km.proc = nil
}

// stop 停止内核子进程（幂等）。
func (km *kernelManager) stop() error {
	km.mu.Lock()
	proc := km.proc
	cmd := km.cmd
	exitCh := km.exitCh
	km.mu.Unlock()

	if proc == nil {
		return nil
	}
	fmt.Printf("正在停止代理 (PID %d)...\n", proc.Pid)

	if runtime.GOOS == "windows" {
		_ = exec.Command("taskkill", "/PID", strconv.Itoa(proc.Pid), "/T", "/F").Run()
		select {
		case <-exitCh:
		case <-time.After(8 * time.Second):
		}
	} else {
		if cmd != nil && cmd.Process != nil {
			_ = proc.Signal(syscall.SIGINT)
		}
		select {
		case <-exitCh:
		case <-time.After(5 * time.Second):
			_ = proc.Kill()
			select {
			case <-exitCh:
			case <-time.After(5 * time.Second):
			}
		}
	}

	km.mu.Lock()
	km.cleanupLocked()
	km.mu.Unlock()
	fmt.Println(green("✓ 代理已停止"))
	return nil
}

func checkPortFree(port int) error {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	return l.Close()
}

func waitPort(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// ---------------- TUI ----------------

func readLine(r *bufio.Reader) (string, bool) {
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return "", false // EOF
	}
	return strings.TrimRight(line, "\r\n"), true
}

func pause(r *bufio.Reader) {
	fmt.Print("按回车返回主菜单...")
	readLine(r) //nolint:errcheck // EOF 时同样返回
	fmt.Println()
}

func statusText() string {
	cur := currentName()
	if cur == "" {
		cur = "（无）"
	}
	st := "未运行"
	if pid, ok := km.runningPID(); ok {
		st = fmt.Sprintf("运行中 (PID %d)", pid)
	}
	return fmt.Sprintf("当前: %s  代理: %s", truncateWidth(cur, 16), st)
}

func printMenu() {
	w := boxWidth
	fmt.Println()
	fmt.Println("╔" + strings.Repeat("═", w-2) + "╗")
	fmt.Println(boxLine("H3 REALITY Client v"+version, w))
	fmt.Println(boxLine(statusText(), w))
	fmt.Println("╠" + strings.Repeat("═", w-2) + "╣")
	fmt.Println(boxLine("[1] 添加配置（粘贴 VLESS 链接）", w))
	fmt.Println(boxLine("[2] 配置列表 / 切换当前配置", w))
	fmt.Println(boxLine("[3] 启动代理", w))
	fmt.Println(boxLine("[4] 停止代理", w))
	fmt.Println(boxLine("[5] 删除配置", w))
	fmt.Println(boxLine("[6] 重命名配置", w))
	fmt.Println(boxLine("[0] 退出", w))
	fmt.Println("╚" + strings.Repeat("═", w-2) + "╝")
}

func printConfigList(cfgs []VlessConfig, cur string) {
	for i, c := range cfgs {
		mark := "    "
		if c.Name == cur {
			mark = green(" [当前]")
		}
		info := fmt.Sprintf("%s:%d  sni=%s", c.Host, c.Port, c.SNI)
		fmt.Printf("  %d. %s%s  %s\n", i+1, truncateWidth(c.Name, 28), mark, truncateWidth(info, 40))
	}
}

func actionAdd(r *bufio.Reader) {
	fmt.Println(cyan("── 添加配置 ──"))
	fmt.Println("请粘贴 VLESS 分享链接，然后回车：")
	link, ok := readLine(r)
	if !ok {
		return
	}
	cfg, err := parseVless(link)
	if err != nil {
		fmt.Println(red("✗ 解析失败: ") + err.Error())
		pause(r)
		return
	}
	fmt.Println(green("✓ 解析成功，参数如下："))
	printCfgSummary(cfg)
	fmt.Printf("保存名称（回车使用默认 \"%s\"）: ", cfg.Name)
	if nameLine, ok := readLine(r); ok {
		if name := strings.TrimSpace(nameLine); name != "" {
			cfg.Name = name
		}
	}
	if err := addConfig(cfg); err != nil {
		fmt.Println(red("✗ 保存失败: ") + err.Error())
	} else {
		fmt.Println(green("✓ 已保存配置: " + cfg.Name))
	}
	pause(r)
}

func actionList(r *bufio.Reader) {
	cfgs, err := loadConfigs()
	if err != nil {
		fmt.Println(red("✗ 读取配置失败: ") + err.Error())
		pause(r)
		return
	}
	if len(cfgs) == 0 {
		fmt.Println(yellow("暂无配置，请先 [1] 添加配置"))
		pause(r)
		return
	}
	fmt.Println(cyan("── 配置列表 ──"))
	printConfigList(cfgs, currentName())
	fmt.Print("输入编号切换当前配置（直接回车返回）: ")
	line, ok := readLine(r)
	if !ok {
		return
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	n, err := strconv.Atoi(line)
	if err != nil || n < 1 || n > len(cfgs) {
		fmt.Println(red("✗ 编号无效: ") + line)
		pause(r)
		return
	}
	name := cfgs[n-1].Name
	if err := withConfigLock(func() error { return writeCurrent(name) }); err != nil {
		fmt.Println(red("✗ 切换失败: ") + err.Error())
	} else {
		fmt.Println(green("✓ 已切换当前配置为: " + name))
	}
	pause(r)
}

func actionStart(r *bufio.Reader) {
	cur := currentName()
	if cur == "" {
		fmt.Println(red("✗ 尚未选择当前配置，请先 [2] 配置列表 中选择"))
		pause(r)
		return
	}
	cfgs, err := loadConfigs()
	if err != nil {
		fmt.Println(red("✗ 读取配置失败: ") + err.Error())
		pause(r)
		return
	}
	var target *VlessConfig
	for i := range cfgs {
		if cfgs[i].Name == cur {
			target = &cfgs[i]
			break
		}
	}
	if target == nil {
		fmt.Println(red("✗ 当前配置已不存在，请重新选择"))
		pause(r)
		return
	}
	if _, ok := km.runningPID(); ok {
		fmt.Println(yellow("代理已在运行，无需重复启动"))
		pause(r)
		return
	}

	fmt.Println("正在释放内嵌内核与规则文件并启动代理...")
	if err := km.start(target); err != nil {
		fmt.Println(red("✗ 启动失败: ") + err.Error())
		pause(r)
		return
	}
	pid, _ := km.runningPID()
	fmt.Println(green(fmt.Sprintf("✓ 代理运行中 (PID %d)", pid)))
	fmt.Println(cyan("  SOCKS5 代理: 127.0.0.1:10808"))
	fmt.Println(cyan("  HTTP  代理: 127.0.0.1:10809"))
	fmt.Println(yellow("按回车返回主菜单（代理继续运行，内核日志实时输出）"))
	readLine(r) //nolint:errcheck
}

func actionStop(r *bufio.Reader) {
	if _, ok := km.runningPID(); !ok {
		fmt.Println(yellow("当前没有运行中的代理"))
		pause(r)
		return
	}
	_ = km.stop()
	pause(r)
}

func actionDelete(r *bufio.Reader) {
	cfgs, err := loadConfigs()
	if err != nil {
		fmt.Println(red("✗ 读取配置失败: ") + err.Error())
		pause(r)
		return
	}
	if len(cfgs) == 0 {
		fmt.Println(yellow("暂无配置"))
		pause(r)
		return
	}
	fmt.Println(cyan("── 删除配置 ──"))
	printConfigList(cfgs, currentName())
	fmt.Print("输入要删除的编号: ")
	line, ok := readLine(r)
	if !ok {
		return
	}
	line = strings.TrimSpace(line)
	n, err := strconv.Atoi(line)
	if err != nil || n < 1 || n > len(cfgs) {
		fmt.Println(red("✗ 编号无效: ") + line)
		pause(r)
		return
	}
	name := cfgs[n-1].Name
	fmt.Printf("确认删除配置 [%s]？（y/N）: ", name)
	ansLine, ok := readLine(r)
	if !ok {
		return
	}
	ans := strings.ToLower(strings.TrimSpace(ansLine))
	if ans != "y" && ans != "yes" {
		fmt.Println(yellow("已取消"))
		pause(r)
		return
	}
	if err := removeConfig(name); err != nil {
		fmt.Println(red("✗ 删除失败: ") + err.Error())
	} else {
		fmt.Println(green("✓ 已删除配置: " + name))
	}
	pause(r)
}

func actionRename(r *bufio.Reader) {
	cfgs, err := loadConfigs()
	if err != nil {
		fmt.Println(red("✗ 读取配置失败: ") + err.Error())
		pause(r)
		return
	}
	if len(cfgs) == 0 {
		fmt.Println(yellow("暂无配置"))
		pause(r)
		return
	}
	fmt.Println(cyan("── 重命名配置 ──"))
	printConfigList(cfgs, currentName())
	fmt.Print("输入要重命名的编号: ")
	line, ok := readLine(r)
	if !ok {
		return
	}
	line = strings.TrimSpace(line)
	n, err := strconv.Atoi(line)
	if err != nil || n < 1 || n > len(cfgs) {
		fmt.Println(red("✗ 编号无效: ") + line)
		pause(r)
		return
	}
	old := cfgs[n-1].Name
	fmt.Printf("输入新名称（当前: %s）: ", old)
	newLine, ok := readLine(r)
	if !ok {
		return
	}
	newName := strings.TrimSpace(newLine)
	if newName == "" || newName == old {
		fmt.Println(yellow("名称未变化，已取消"))
		pause(r)
		return
	}
	if err := renameConfig(old, newName); err != nil {
		fmt.Println(red("✗ 重命名失败: ") + err.Error())
	} else {
		fmt.Println(green("✓ 已重命名为: " + newName))
	}
	pause(r)
}

func run() {
	r := bufio.NewReader(os.Stdin)
	fmt.Println(cyan("H3 REALITY Client v" + version + " — 单文件 TUI 客户端"))
	fmt.Println("本地代理端口：SOCKS5 " + strconv.Itoa(socksPort) + " / HTTP " + strconv.Itoa(httpPort) + "，规则：绕过大陆（国内直连）")
	for {
		printMenu()
		fmt.Print("请选择: ")
		line, ok := readLine(r)
		if !ok {
			fmt.Println()
			return // 输入流结束，退出
		}
		choice := strings.TrimSpace(line)
		if choice == "" {
			continue // 空输入：静默重绘菜单
		}
		switch choice {
		case "1":
			actionAdd(r)
		case "2":
			actionList(r)
		case "3":
			actionStart(r)
		case "4":
			actionStop(r)
		case "5":
			actionDelete(r)
		case "6":
			actionRename(r)
		case "0":
			fmt.Println(green("正在退出..."))
			return
		default:
			fmt.Println(red("✗ 无效选择: ") + choice)
		}
	}
}

func main() {
	setupConsole()
	colorOn = colorEnabled()

	sigCh := make(chan os.Signal, 1)
	sigList := []os.Signal{os.Interrupt}
	if runtime.GOOS != "windows" {
		sigList = append(sigList, syscall.SIGTERM)
	}
	signal.Notify(sigCh, sigList...)
	go func() {
		s := <-sigCh
		fmt.Printf("\n收到信号 %v，正在停止代理并退出...\n", s)
		_ = km.stop()
		_ = os.Remove(filepath.Join(programDir(), lockFile))
		os.Exit(0)
	}()

	defer func() {
		_ = km.stop()
		_ = os.Remove(filepath.Join(programDir(), lockFile))
	}()

	run()
}
