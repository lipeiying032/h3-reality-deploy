package main

import (
	"encoding/json"
	"strings"
	"testing"
)

const testLink = "vless://3f2a1c4e-5b6d-4e7f-8a90-1b2c3d4e5f60@203.0.113.7:8446?encryption=none&security=reality&type=xhttp&mode=stream-one&enableH3=1&path=%2Fv1%2Fcollect&sni=ea.com&fp=chrome&pbk=bYvOZAoxgMKpI6Sc_18iBdlnHSa0dL-DXfSoAeupolQ&sid=1a2b3c4d&host=ea.com&alpn=h3#H3-REALITY-8446"

func TestParseVlessFullFields(t *testing.T) {
	cfg, err := parseVless(testLink)
	if err != nil {
		t.Fatalf("parseVless 失败: %v", err)
	}
	want := map[string]string{
		"UUID":   "3f2a1c4e-5b6d-4e7f-8a90-1b2c3d4e5f60",
		"Host":   "203.0.113.7",
		"Path":   "/v1/collect",
		"SNI":    "ea.com",
		"FP":     "chrome",
		"PBK":    "bYvOZAoxgMKpI6Sc_18iBdlnHSa0dL-DXfSoAeupolQ",
		"SID":    "1a2b3c4d",
		"ALPN":   "h3",
		"Mode":   "stream-one",
		"Remark": "H3-REALITY-8446",
		"Name":   "H3-REALITY-8446",
	}
	got := map[string]string{
		"UUID":   cfg.UUID,
		"Host":   cfg.Host,
		"Path":   cfg.Path,
		"SNI":    cfg.SNI,
		"FP":     cfg.FP,
		"PBK":    cfg.PBK,
		"SID":    cfg.SID,
		"ALPN":   cfg.ALPN,
		"Mode":   cfg.Mode,
		"Remark": cfg.Remark,
		"Name":   cfg.Name,
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("字段 %s = %q，期望 %q", k, got[k], w)
		}
	}
	if cfg.Port != 8446 {
		t.Errorf("Port = %d，期望 8446", cfg.Port)
	}
	if cfg.HostParam != "ea.com" {
		t.Errorf("HostParam = %q，期望 ea.com", cfg.HostParam)
	}
	if cfg.Link != testLink {
		t.Errorf("Link 未保留原始链接")
	}
}

func TestParseVlessEncodedRemarkAndDefaults(t *testing.T) {
	link := "vless://3f2a1c4e-5b6d-4e7f-8a90-1b2c3d4e5f60@example.com:443?security=reality&type=xhttp&path=%2Fcollect%2Fdata&sni=example.com&pbk=abc#%E6%B5%8B%E8%AF%95%E8%8A%82%E7%82%B9"
	cfg, err := parseVless(link)
	if err != nil {
		t.Fatalf("parseVless 失败: %v", err)
	}
	if cfg.Remark != "测试节点" {
		t.Errorf("Remark = %q，期望 测试节点（应做 URL 解码）", cfg.Remark)
	}
	if cfg.Path != "/collect/data" {
		t.Errorf("Path = %q，期望 /collect/data（应做 URL 解码）", cfg.Path)
	}
	if cfg.FP != "chrome" {
		t.Errorf("默认 FP = %q，期望 chrome", cfg.FP)
	}
	if cfg.ALPN != "h3" {
		t.Errorf("默认 ALPN = %q，期望 h3", cfg.ALPN)
	}
	if cfg.Mode != "stream-one" {
		t.Errorf("默认 Mode = %q，期望 stream-one", cfg.Mode)
	}
	if cfg.Name != "测试节点" {
		t.Errorf("默认 Name = %q，期望取自备注", cfg.Name)
	}
}

func TestParseVlessIPv6(t *testing.T) {
	link := "vless://3f2a1c4e-5b6d-4e7f-8a90-1b2c3d4e5f60@[2001:db8::1]:8446?security=reality&type=xhttp&sni=a.com&pbk=b#v6"
	cfg, err := parseVless(link)
	if err != nil {
		t.Fatalf("parseVless 失败: %v", err)
	}
	if cfg.Host != "2001:db8::1" {
		t.Errorf("Host = %q，期望 2001:db8::1", cfg.Host)
	}
	if cfg.Port != 8446 {
		t.Errorf("Port = %d，期望 8446", cfg.Port)
	}
}

func TestParseVlessErrors(t *testing.T) {
	bad := []struct {
		name string
		link string
		want string
	}{
		{"空链接", "", "为空"},
		{"非 vless", "ss://abc", "不是 vless"},
		{"缺少@", "vless://not-a-link", "@"},
		{"UUID 非法", "vless://12345@host:443?security=reality&type=xhttp&sni=a&pbk=b", "UUID"},
		{"端口非法", "vless://3f2a1c4e-5b6d-4e7f-8a90-1b2c3d4e5f60@host:99999?security=reality&type=xhttp&sni=a&pbk=b", "端口"},
		{"非 reality", "vless://3f2a1c4e-5b6d-4e7f-8a90-1b2c3d4e5f60@host:443?security=tls&type=xhttp&sni=a&pbk=b", "REALITY"},
		{"非 xhttp", "vless://3f2a1c4e-5b6d-4e7f-8a90-1b2c3d4e5f60@host:443?security=reality&type=tcp&sni=a&pbk=b", "xhttp"},
		{"缺 pbk", "vless://3f2a1c4e-5b6d-4e7f-8a90-1b2c3d4e5f60@host:443?security=reality&type=xhttp&sni=a", "pbk"},
		{"缺 sni", "vless://3f2a1c4e-5b6d-4e7f-8a90-1b2c3d4e5f60@host:443?security=reality&type=xhttp&pbk=b", "sni"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseVless(tc.link); err == nil {
				t.Fatalf("期望解析失败，却成功了: %s", tc.link)
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("错误信息 %q 未包含 %q", err.Error(), tc.want)
			}
		})
	}
}

func TestBuildXrayConfig(t *testing.T) {
	cfg, err := parseVless(testLink)
	if err != nil {
		t.Fatalf("parseVless 失败: %v", err)
	}
	data, err := buildXrayConfig(cfg)
	if err != nil {
		t.Fatalf("buildXrayConfig 失败: %v", err)
	}
	var xc struct {
		Log struct {
			LogLevel string `json:"loglevel"`
		} `json:"log"`
		Inbounds []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
			Port     int    `json:"port"`
		} `json:"inbounds"`
		Outbounds []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
			Settings struct {
				Vnext []struct {
					Address string `json:"address"`
					Port    int    `json:"port"`
					Users   []struct {
						ID         string `json:"id"`
						Encryption string `json:"encryption"`
					} `json:"users"`
				} `json:"vnext"`
			} `json:"settings"`
			StreamSettings struct {
				Network       string `json:"network"`
				Security      string `json:"security"`
				XHTTPSettings struct {
					Mode     string `json:"mode"`
					EnableH3 bool   `json:"enableH3"`
					Path     string `json:"path"`
				} `json:"xhttpSettings"`
				RealitySettings struct {
					ServerName  string   `json:"serverName"`
					Fingerprint string   `json:"fingerprint"`
					PublicKey   string   `json:"publicKey"`
					ShortID     string   `json:"shortId"`
					Alpn        []string `json:"alpn"`
				} `json:"realitySettings"`
			} `json:"streamSettings"`
		} `json:"outbounds"`
		Routing struct {
			DomainStrategy string `json:"domainStrategy"`
			Rules          []struct {
				Type        string   `json:"type"`
				Domain      []string `json:"domain"`
				IP          []string `json:"ip"`
				Network     string   `json:"network"`
				OutboundTag string   `json:"outboundTag"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(data, &xc); err != nil {
		t.Fatalf("生成的配置不是合法 JSON: %v", err)
	}

	if len(xc.Inbounds) != 2 {
		t.Fatalf("Inbounds 数量 = %d，期望 2 (socks+http)", len(xc.Inbounds))
	}
	if xc.Inbounds[0].Protocol != "socks" || xc.Inbounds[0].Port != 10808 {
		t.Errorf("socks inbound 不正确: %+v", xc.Inbounds[0])
	}
	if xc.Inbounds[1].Protocol != "http" || xc.Inbounds[1].Port != 10809 {
		t.Errorf("http inbound 不正确: %+v", xc.Inbounds[1])
	}

	if len(xc.Outbounds) != 3 {
		t.Fatalf("Outbounds 数量 = %d，期望 3", len(xc.Outbounds))
	}
	proxy := xc.Outbounds[0]
	if proxy.Protocol != "vless" || proxy.StreamSettings.Network != "xhttp" || proxy.StreamSettings.Security != "reality" {
		t.Errorf("proxy outbound 参数不正确: %+v", proxy)
	}
	v := proxy.Settings.Vnext[0]
	if v.Address != "203.0.113.7" || v.Port != 8446 || v.Users[0].ID != "3f2a1c4e-5b6d-4e7f-8a90-1b2c3d4e5f60" || v.Users[0].Encryption != "none" {
		t.Errorf("vnext 参数不正确: %+v", v)
	}
	if proxy.StreamSettings.XHTTPSettings.Mode != "stream-one" || !proxy.StreamSettings.XHTTPSettings.EnableH3 || proxy.StreamSettings.XHTTPSettings.Path != "/v1/collect" {
		t.Errorf("xhttpSettings 不正确: %+v", proxy.StreamSettings.XHTTPSettings)
	}
	rs := proxy.StreamSettings.RealitySettings
	if rs.ServerName != "ea.com" || rs.PublicKey != "bYvOZAoxgMKpI6Sc_18iBdlnHSa0dL-DXfSoAeupolQ" || rs.ShortID != "1a2b3c4d" || rs.Fingerprint != "chrome" {
		t.Errorf("realitySettings 不正确: %+v", rs)
	}
	if len(rs.Alpn) != 1 || rs.Alpn[0] != "h3" {
		t.Errorf("alpn 不正确: %v", rs.Alpn)
	}

	if xc.Routing.DomainStrategy != "IPIfNonMatch" {
		t.Errorf("domainStrategy = %q", xc.Routing.DomainStrategy)
	}
	if len(xc.Routing.Rules) != 4 {
		t.Fatalf("routing rules 数量 = %d，期望 4", len(xc.Routing.Rules))
	}
	byTag := map[string]string{}
	for _, rl := range xc.Routing.Rules {
		if len(rl.Domain) > 0 {
			byTag["d:"+rl.Domain[0]] = rl.OutboundTag
		}
		if len(rl.IP) > 0 {
			byTag["i:"+rl.IP[0]] = rl.OutboundTag
		}
		if rl.Network != "" {
			byTag["n:"+rl.Network] = rl.OutboundTag
		}
	}
	if byTag["d:geosite:cn"] != "direct" || byTag["i:geoip:cn"] != "direct" ||
		byTag["d:geosite:geolocation-!cn"] != "proxy" || byTag["n:tcp,udp"] != "proxy" {
		t.Errorf("绕过大陆规则不正确: %v", byTag)
	}
}
