// Copyright (C) 2026 The Syncthing Authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package connections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/syncthing/syncthing/lib/config"
)

const (
	// tailcatIdentityFile is the file in the config directory holding the
	// persistent tailcat identity of this device, i.e. the keys that its
	// tailcat address is derived from.
	tailcatIdentityFile = "tailcat-identity.json"

	// tailcatDialTimeout bounds the setup of a tailcat tunnel, which may
	// involve fetching a DERP map and hole punching.
	tailcatDialTimeout = time.Minute
)

// Tailcat transport
//
// A tailcat peer pair is a tailcat server (listener) and a tailcat client
// (dialer). The server's address, a "tailcat address", is shared out of band:
// it is what another device needs to dial us. We keep our server identity in
// the config directory so that our address survives restarts, and we keep one
// tailcat client per peer address so that repeated dials reuse the same
// WireGuard tunnel.
//
// Addresses look like
//
//	tailcat://<tailcat address>:<port inside the tunnel>
//
// where the port is ordinarily 22000, as with the TCP transport.

// tailcatIdentity is the persisted identity of our tailcat server.
type tailcatIdentity struct {
	Key          key.NodePrivate      `json:"key"`
	PresharedKey tailcat.PresharedKey `json:"presharedKey"`

	// RegionID is the DERP region we bootstrap through. It is chosen once,
	// when the identity is created, and persisted: our tailcat address is
	// derived from it, so a stable region keeps the address the same across
	// restarts.
	RegionID tailcfg.DERPRegionID `json:"regionID,omitempty"`
}

// tailcatLinks holds the process wide tailcat state: our server and the
// clients we use to reach peers.
type tailcatLinks struct {
	mu       sync.Mutex
	srv      *tailcat.Server
	addr     tailcat.Addr // non-empty once the server has started
	err      error        // last failure to start the server
	identity tailcatIdentity
	clients  map[tailcat.Addr]*tailcat.Client
}

var tcLinks = &tailcatLinks{
	clients: make(map[tailcat.Addr]*tailcat.Client),
}

// server returns our tailcat server, creating it (and our persistent
// identity, if this is the first run) as needed. The server is not started;
// the first successful call to its Listen method does that.
func (l *tailcatLinks) server(ctx context.Context, configPath string) (*tailcat.Server, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.srv != nil {
		return l.srv, nil
	}
	identity, _, err := loadTailcatIdentity(ctx, configPath)
	if err != nil {
		l.err = err
		return nil, err
	}
	l.identity = identity
	l.srv = &tailcat.Server{
		Key:          identity.Key,
		PresharedKey: identity.PresharedKey,
		RegionID:     identity.RegionID,
		Logf:         tailcatLogf,
	}
	return l.srv, nil
}

// serverStarted records that the given server is up, making its address
// available for sharing. The address is derived from the persisted identity,
// not from the server, so that it is byte for byte the same on every start.
func (l *tailcatLinks) serverStarted(server *tailcat.Server) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.srv != server {
		return
	}
	addr, err := tailcatAddr(l.identity)
	if err != nil {
		l.err = err
		return
	}
	l.addr = addr
	l.err = nil
}

// serverFailed records why the server could not be started.
func (l *tailcatLinks) serverFailed(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.err = err
}

// status returns our tailcat address and the reason there is none, if any.
func (l *tailcatLinks) status() (tailcat.Addr, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.addr != "" {
		return l.addr, nil
	}
	if l.err != nil {
		return "", l.err
	}
	return "", errors.New("tailcat is not listening")
}

// client returns a tailcat client for the given peer address, creating it on
// first use. Clients are reused for the lifetime of the process so that the
// WireGuard tunnel to a peer is set up once, not once per dial.
func (l *tailcatLinks) client(addr tailcat.Addr) *tailcat.Client {
	l.mu.Lock()
	defer l.mu.Unlock()
	if client, ok := l.clients[addr]; ok {
		return client
	}
	client := tailcat.NewClient(addr)
	client.Logf = tailcatLogf
	l.clients[addr] = client
	return client
}

// dial opens a TCP connection to the given port of the peer at the given
// tailcat address.
func (l *tailcatLinks) dial(ctx context.Context, addr tailcat.Addr, port uint16) (net.Conn, error) {
	return l.client(addr).DialTCPPort(ctx, port)
}

func tailcatLogf(format string, args ...any) {
	l.Debugf("tailcat: "+format, args...)
}

// tailcatAddr returns the public address of the given identity. It contains
// the keys and the DERP region ID, but not the DERP nodes, so it is short and
// can be derived again on every start without changing.
func tailcatAddr(identity tailcatIdentity) (tailcat.Addr, error) {
	if identity.Key.IsZero() {
		return "", errors.New("no tailcat key")
	}
	if identity.RegionID == 0 {
		return "", errors.New("no tailcat DERP region")
	}
	return (&tailcat.ConnInfo{
		ServerPublic:      tailcat.NodePublic{NodePublic: identity.Key.Public()},
		ServerDiscoPublic: tailcat.DiscoPublicForNode(identity.Key),
		PresharedKey:      identity.PresharedKey,
		RegionID:          identity.RegionID,
	}).Addr(), nil
}

// chooseTailcatRegion picks the DERP region to bootstrap through. The choice
// is made once, when the identity is created, and persisted, so that the
// tailcat address doesn't change when the nearest region does.
func chooseTailcatRegion(ctx context.Context) (tailcfg.DERPRegionID, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Expanding a "-1" region lets the tailcat library do its normal
	// netcheck based selection, including its fallback to a random region
	// when netcheck fails, and then tell us which region it picked.
	ci := &tailcat.ConnInfo{RegionID: -1}
	if err := ci.Expand(ctx, tailcat.ExpandForServer); err != nil {
		return 0, fmt.Errorf("choosing tailcat DERP region: %w", err)
	}
	if len(ci.Region) == 0 || ci.Region[0] == nil || ci.Region[0].RegionID == 0 {
		return 0, errors.New("no tailcat DERP region available")
	}
	return ci.Region[0].RegionID, nil
}

// saveTailcatIdentity writes the identity to the given path.
func saveTailcatIdentity(path string, identity tailcatIdentity) error {
	bs, err := json.MarshalIndent(identity, "", "\t")
	if err != nil {
		return fmt.Errorf("encoding tailcat identity: %w", err)
	}
	if err := os.WriteFile(path, bs, 0o600); err != nil {
		return fmt.Errorf("saving tailcat identity: %w", err)
	}
	return nil
}

// loadTailcatIdentity reads our tailcat identity from the config directory,
// creating and saving a new one when there is none, and returns the file it
// lives in. The DERP region is chosen and persisted at the same time, so that
// the address derived from the identity is the same on every start.
func loadTailcatIdentity(ctx context.Context, configPath string) (tailcatIdentity, string, error) {
	path := filepath.Join(filepath.Dir(configPath), tailcatIdentityFile)

	bs, err := os.ReadFile(path)
	if err == nil {
		var identity tailcatIdentity
		if err := json.Unmarshal(bs, &identity); err != nil {
			return tailcatIdentity{}, path, fmt.Errorf("parsing tailcat identity: %w", err)
		}
		if identity.Key.IsZero() || identity.PresharedKey.IsZero() {
			return tailcatIdentity{}, path, fmt.Errorf("incomplete tailcat identity in %s", path)
		}
		if identity.RegionID == 0 {
			// Identity written before the region was persisted; choose
			// one now and store it.
			region, err := chooseTailcatRegion(ctx)
			if err != nil {
				return tailcatIdentity{}, path, err
			}
			identity.RegionID = region
			if err := saveTailcatIdentity(path, identity); err != nil {
				return tailcatIdentity{}, path, err
			}
		}
		return identity, path, nil
	} else if !os.IsNotExist(err) {
		return tailcatIdentity{}, path, err
	}

	region, err := chooseTailcatRegion(ctx)
	if err != nil {
		return tailcatIdentity{}, path, err
	}
	identity := tailcatIdentity{
		Key:          key.NewNode(),
		PresharedKey: tailcat.NewPresharedKey(),
		RegionID:     region,
	}
	if err := saveTailcatIdentity(path, identity); err != nil {
		return tailcatIdentity{}, path, err
	}
	return identity, path, nil
}

// tailcatURI returns the canonical address of the given tailcat address and
// in-tunnel port.
func tailcatURI(addr tailcat.Addr, port uint16) string {
	return (&url.URL{
		Scheme: "tailcat",
		Host:   net.JoinHostPort(string(addr), strconv.Itoa(int(port))),
	}).String()
}

// tailcatPort returns the port inside the tunnel of a tailcat URI, defaulting
// to the default BEP port.
func tailcatPort(uri *url.URL) (uint16, error) {
	portStr := uri.Port()
	if portStr == "" {
		return uint16(config.DefaultTCPPort), nil
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid tailcat port %q: %w", portStr, err)
	}
	return uint16(port), nil
}

// parseTailcatAddr splits a tailcat address, as entered by a user or found in
// the device configuration, into the tailcat address proper and the port
// inside the tunnel. The address may be given with or without the tailcat://
// scheme and port.
func parseTailcatAddr(address string) (tailcat.Addr, uint16, error) {
	// A tailcat address contains no whitespace, so removing it all makes
	// line-wrapped pasted addresses work.
	address = strings.Join(strings.Fields(address), "")
	if address == "" {
		return "", 0, errors.New("no tailcat address given")
	}
	if !strings.Contains(address, "://") {
		address = "tailcat://" + address
	}
	uri, err := url.Parse(address)
	if err != nil {
		return "", 0, fmt.Errorf("invalid tailcat address: %w", err)
	}
	if uri.Scheme != "tailcat" {
		return "", 0, fmt.Errorf("invalid tailcat address scheme %q", uri.Scheme)
	}

	port, err := tailcatPort(uri)
	if err != nil {
		return "", 0, err
	}

	addr := tailcat.Addr(uri.Hostname())
	if addr == "" {
		return "", 0, errors.New("no tailcat address given")
	}
	if _, err := tailcat.ParseAddr(addr); err != nil {
		return "", 0, fmt.Errorf("invalid tailcat address: %w", err)
	}
	return addr, port, nil
}
