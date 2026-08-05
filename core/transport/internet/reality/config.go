package reality

import (
	"context"
	"io"
	"net"
	"os"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/xtls/reality"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func (c *Config) GetREALITYConfig() *reality.Config {
	var dialer net.Dialer
	config := &reality.Config{
		DialContext: dialer.DialContext,

		Show: c.Show,
		Type: c.Type,
		Dest: c.Dest,
		Xver: byte(c.Xver),

		PrivateKey:   c.PrivateKey,
		MinClientVer: c.MinClientVer,
		MaxClientVer: c.MaxClientVer,
		MaxTimeDiff:  time.Duration(c.MaxTimeDiff) * time.Millisecond,

		NextProtos:             c.Alpn, // nil by default; set to ["h3"] only for XHTTP/3 (REALITY over QUIC)
		SessionTicketsDisabled: true,

		KeyLogWriter: KeyLogWriterFromConfig(c),
	}
	if c.Mldsa65Seed != nil {
		_, key := mldsa65.NewKeyFromSeed((*[32]byte)(c.Mldsa65Seed))
		config.Mldsa65Key = key.Bytes()
	}
	if c.LimitFallbackUpload != nil {
		config.LimitFallbackUpload.AfterBytes = c.LimitFallbackUpload.AfterBytes
		config.LimitFallbackUpload.BytesPerSec = c.LimitFallbackUpload.BytesPerSec
		config.LimitFallbackUpload.BurstBytesPerSec = c.LimitFallbackUpload.BurstBytesPerSec
	}
	if c.LimitFallbackDownload != nil {
		config.LimitFallbackDownload.AfterBytes = c.LimitFallbackDownload.AfterBytes
		config.LimitFallbackDownload.BytesPerSec = c.LimitFallbackDownload.BytesPerSec
		config.LimitFallbackDownload.BurstBytesPerSec = c.LimitFallbackDownload.BurstBytesPerSec
	}
	config.ServerNames = make(map[string]bool)
	for _, serverName := range c.ServerNames {
		config.ServerNames[serverName] = true
	}
	config.ShortIds = make(map[[8]byte]bool)
	for _, shortId := range c.ShortIds {
		config.ShortIds[*(*[8]byte)(shortId)] = true
	}
	return config
}

// GetRealityQUICParams builds the parameters used for REALITY over QUIC
// (XHTTP/3) in the C-gamma data-plane-auth design. The handshake carries no
// REALITY payload; the secrets and bounds here are consumed by the HTTP-layer
// X-Reality-Auth verification (server) and record construction (client).
func (c *Config) GetRealityQUICParams() *tls.RealityQUICParams {
	params := &tls.RealityQUICParams{
		PrivateKey:   c.PrivateKey,
		MinClientVer: c.MinClientVer,
		MaxClientVer: c.MaxClientVer,
		MaxTimeDiff:  time.Duration(c.MaxTimeDiff) * time.Millisecond,
		PublicKey:    c.PublicKey,
		ShortId:      c.ShortId,
		ServerName:   c.ServerName,
		Alpn:         c.Alpn,
		Show:         c.Show,
		Dest:         c.Dest,
	}
	if len(c.ServerNames) > 0 {
		params.DestServerName = c.ServerNames[0]
	}
	params.ServerNames = make(map[string]bool, len(c.ServerNames))
	for _, serverName := range c.ServerNames {
		params.ServerNames[serverName] = true
	}
	// The QUIC precheck relays probe flows to the fallback dest. It only
	// activates when fallbackDest is explicitly configured (the hub gates on
	// FallbackDest != ""): defaulting to Dest here would relay every
	// no-session_id ClientHello — including the C-gamma data-plane client,
	// whose authentication lives in X-Reality-Auth at the HTTP layer — and
	// break the normal data path.
	params.FallbackDest = c.FallbackDest
	params.FallbackDestRoutes = c.FallbackDestRoutes
	params.FallbackTimeout = 120 * time.Second
	if len(c.ShortIds) > 0 {
		params.ShortIds = make(map[[8]byte]bool, len(c.ShortIds))
		for _, shortId := range c.ShortIds {
			params.ShortIds[*(*[8]byte)(shortId)] = true
		}
	}
	return params
}

func KeyLogWriterFromConfig(c *Config) io.Writer {
	if len(c.MasterKeyLog) <= 0 || c.MasterKeyLog == "none" {
		return nil
	}

	writer, err := os.OpenFile(c.MasterKeyLog, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "failed to open ", c.MasterKeyLog, " as master key log")
	}

	return writer
}

func ConfigFromStreamSettings(settings *internet.MemoryStreamConfig) *Config {
	if settings == nil {
		return nil
	}
	config, ok := settings.SecuritySettings.(*Config)
	if !ok {
		return nil
	}
	return config
}
