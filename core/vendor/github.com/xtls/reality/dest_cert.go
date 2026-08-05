package reality

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// destCertCacheTTL is how long a fetched dest certificate chain is reused
// before the server dials Dest again. Real site certificates are stable and
// rotate rarely, so 24h is a safe default.
const destCertCacheTTL = 24 * time.Hour

// destCertDialTimeout bounds a single TCP+TLS handshake against Dest. Dest
// connectivity problems must never stall the REALITY server for long: on
// failure the server falls back to its built-in self-signed certificate
// within the client's handshake timeout.
const destCertDialTimeout = 3 * time.Second

// destCertFailBackoff is how long a failed Dest probe is remembered before
// the server tries dialing Dest again, so a broken Dest does not stall every
// handshake (and hammer Dest with retries).
const destCertFailBackoff = 60 * time.Second

// destCertEntry is the cached result of a Dest probe. done is non-nil while a
// fetch is in flight so that concurrent handshakes wait for the same result
// instead of stampeding Dest.
type destCertEntry struct {
	chain     [][]byte
	fetchedAt time.Time
	failedAt  time.Time
	done      chan struct{}
}

var (
	destCertMu   sync.Mutex
	destCertData = map[string]*destCertEntry{}
)

// fetchDestCertChain dials Dest over plain TCP with a standard-library TLS
// handshake (SNI + InsecureSkipVerify) and returns the peer's certificate
// chain as DER bytes (leaf first).
//
// TCP is used instead of QUIC on purpose: the certificate chain is pure
// public key data and is identical regardless of the transport it was
// fetched over, so there is no need for a QUIC handshake. Some production
// edges (notably www.apple.com) reject the Go-native QUIC ClientHello
// (CRYPTO_ERROR 0x150: 200:internal error), which made QUIC fetches fail
// and forced the server to fall back to its self-signed certificate. The
// standard-library TCP TLS fingerprint, in contrast, is universally accepted.
// The handshake keys and CertVerify of the server are never reused: the
// REALITY client authenticates the server through the sessionId/X25519
// exchange instead of certificate verification.
func fetchDestCertChain(ctx context.Context, dest, serverName string) ([][]byte, error) {
	addr := dest
	if _, _, err := net.SplitHostPort(addr); err != nil {
		// dest is a bare hostname without a port; default to 443.
		addr = net.JoinHostPort(addr, "443")
	}

	tlsConf := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // we only extract the chain, we do not need to validate Dest
	}
	dialer := &net.Dialer{Timeout: destCertDialTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConf)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("REALITY: dest %s sent no certificates", addr)
	}
	chain := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		chain = append(chain, cert.Raw)
	}
	return chain, nil
}

// GetDestCertChain returns the cached real certificate chain of Dest, dialing
// Dest on a cache miss (singleflight). It returns nil when Dest is not
// configured or cannot be reached; callers then fall back to the built-in
// self-signed certificate.
func GetDestCertChain(ctx context.Context, config *Config) [][]byte {
	dest := strings.TrimSpace(config.Dest)
	if dest == "" {
		return nil
	}
	serverName := strings.TrimSpace(config.DestServerName)
	if serverName == "" {
		if host, _, err := net.SplitHostPort(dest); err == nil {
			serverName = host
		} else {
			serverName = dest
		}
	}
	key := dest + "|" + serverName

	destCertMu.Lock()
	if entry, ok := destCertData[key]; ok {
		if entry.done != nil {
			// A fetch for this Dest is already in flight; wait for it.
			done := entry.done
			destCertMu.Unlock()
			select {
			case <-done:
			case <-ctx.Done():
				return nil
			}
			destCertMu.Lock()
			entry = destCertData[key]
			destCertMu.Unlock()
			if entry != nil && entry.done == nil {
				if len(entry.chain) > 0 {
					return entry.chain
				}
				if time.Since(entry.failedAt) < destCertFailBackoff {
					return nil
				}
			}
			return nil
		}
		if entry.done == nil && time.Since(entry.failedAt) < destCertFailBackoff {
			// Recent failed probe: fall back immediately, do not re-dial.
			destCertMu.Unlock()
			return nil
		}
		if entry.done == nil && time.Since(entry.fetchedAt) < destCertCacheTTL {
			chain := entry.chain
			destCertMu.Unlock()
			return chain
		}
	}
	// Absent or expired: become the fetcher.
	entry := &destCertEntry{done: make(chan struct{})}
	destCertData[key] = entry
	destCertMu.Unlock()

	chain, err := fetchDestCertChain(ctx, dest, serverName)

	destCertMu.Lock()
	if err != nil || len(chain) == 0 {
		done := entry.done
		entry.failedAt = time.Now()
		entry.done = nil
		destCertMu.Unlock()
		close(done)
		if err != nil {
			log.Printf("REALITY: failed to fetch dest certificate chain from %s (SNI %s), falling back to self-signed certificate: %v", dest, serverName, err)
		}
		return nil
	}
	entry.chain = chain
	entry.fetchedAt = time.Now()
	entry.failedAt = time.Time{}
	done := entry.done
	entry.done = nil
	destCertMu.Unlock()
	close(done)

	if leaf, err := x509.ParseCertificate(chain[0]); err == nil {
		sum := sha256.Sum256(chain[0])
		log.Printf("REALITY: using real dest certificate chain from %s (SNI %s): subject %q, leaf sha256 %s, %d cert(s)", dest, serverName, leaf.Subject.String(), hex.EncodeToString(sum[:]), len(chain))
	}
	return chain
}
