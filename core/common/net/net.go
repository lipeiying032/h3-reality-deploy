// Package net is a drop-in replacement to Golang's net package, with some more functionalities.
package net // import "github.com/xtls/xray-core/common/net"

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// ConnIdleTimeout is the maximum time an idle session can survive in the
// tunnel before it is considered dead. It is the client-side default for both
// the QUIC MaxIdleTimeout (splithttp dialer) and the HTTP/1.1 / HTTP/2
// IdleConnTimeout, so the death-detection window stays consistent across HTTP
// versions and transports. 45s shortens the dead-connection window: after the
// peer is cut off, keepalives go unanswered and the connection now fails over
// within seconds instead of lingering up to 5 minutes with a zombie keepalive
// loop. Active sessions are unaffected — only idle sessions are reaped.
const ConnIdleTimeout = 45 * time.Second

// consistent with quic-go
const QuicgoH3KeepAlivePeriod = 10 * time.Second

// consistent with chrome
const ChromeH2KeepAlivePeriod = 45 * time.Second

var ErrNotLocal = errors.New("the source address is not from local machine.")

type localIPCacheEntry struct {
	addrs      []net.Addr
	lastUpdate time.Time
}

var localIPCache = atomic.Pointer[localIPCacheEntry]{}

func IsLocal(ip net.IP) (bool, error) {
	var addrs []net.Addr
	if entry := localIPCache.Load(); entry == nil || time.Since(entry.lastUpdate) > time.Minute {
		var err error
		addrs, err = net.InterfaceAddrs()
		if err != nil {
			return false, err
		}
		localIPCache.Store(&localIPCacheEntry{
			addrs:      addrs,
			lastUpdate: time.Now(),
		})
	} else {
		addrs = entry.addrs
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.Equal(ip) {
				return true, nil
			}
		}
	}
	return false, nil
}
