// Copyright (C) 2026 The Syncthing Authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package connections

import (
	"context"
	"crypto/tls"
	"net/url"
	"time"

	"github.com/syncthing/syncthing/lib/config"
	"github.com/syncthing/syncthing/lib/connections/registry"
	"github.com/syncthing/syncthing/lib/protocol"
)

func init() {
	dialers["tailcat"] = &tailcatDialerFactory{}
}

// tailcatDialer dials a peer through a tailcat tunnel, which is set up by
// the tailcat client pairing with the peer's tailcat server.
type tailcatDialer struct {
	commonDialer
}

func (d *tailcatDialer) Dial(ctx context.Context, _ protocol.DeviceID, uri *url.URL) (internalConn, error) {
	addr, port, err := parseTailcatAddr(uri.String())
	if err != nil {
		return internalConn{}, err
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, tailcatDialTimeout)
	defer cancel()

	conn, err := tcLinks.dial(timeoutCtx, addr, port)
	if err != nil {
		return internalConn{}, err
	}

	tc := tls.Client(conn, d.tlsCfg)
	if err := tlsTimedHandshake(tc); err != nil {
		tc.Close()
		return internalConn{}, err
	}

	return newInternalConn(tc, connTypeTailcatClient, false, d.wanPriority), nil
}

func (d *tailcatDialer) Priority(string) int {
	// A tailcat address is not a host name that could be resolved, and a
	// tailcat tunnel always reaches its peer over the internet.
	return d.wanPriority
}

type tailcatDialerFactory struct{}

func (tailcatDialerFactory) New(opts config.OptionsConfiguration, tlsCfg *tls.Config, _ *registry.Registry, _ *lanChecker) genericDialer {
	return &tailcatDialer{
		commonDialer: commonDialer{
			trafficClass:      opts.TrafficClass,
			reconnectInterval: time.Duration(opts.ReconnectIntervalS) * time.Second,
			tlsCfg:            tlsCfg,
			lanPriority:       opts.ConnectionPriorityTCPLAN,
			wanPriority:       opts.ConnectionPriorityTCPWAN,
			allowsMultiConns:  true,
		},
	}
}

func (tailcatDialerFactory) AlwaysWAN() bool {
	return true
}

func (tailcatDialerFactory) Valid(_ config.Configuration) error {
	// Always valid
	return nil
}

func (tailcatDialerFactory) String() string {
	return "Tailcat Dialer"
}
