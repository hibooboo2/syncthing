// Copyright (C) 2026 The Syncthing Authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package connections

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/url"
	"strconv"
	"sync/atomic"

	"github.com/syncthing/syncthing/internal/slogutil"
	"github.com/syncthing/syncthing/lib/config"
	"github.com/syncthing/syncthing/lib/connections/registry"
	"github.com/syncthing/syncthing/lib/nat"
	"github.com/syncthing/syncthing/lib/svcutil"
)

func init() {
	listeners["tailcat"] = &tailcatListenerFactory{}
}

// tailcatListener accepts peers through our tailcat server. The server and
// its address are shared process wide (see tailcatLinks) so that the address
// we hand out stays the same no matter how often the listener is restarted
// by configuration changes.
type tailcatListener struct {
	svcutil.ServiceWithError
	onAddressesChangedNotifier

	uri     *url.URL
	cfg     config.Wrapper
	tlsCfg  *tls.Config
	conns   chan internalConn
	factory listenerFactory

	running atomic.Bool
}

func (t *tailcatListener) serve(ctx context.Context) error {
	port, err := tailcatPort(t.uri)
	if err != nil {
		slog.WarnContext(ctx, "Failed to listen (tailcat)", slogutil.Error(err))
		return err
	}

	server, err := tcLinks.server(t.cfg.ConfigPath())
	if err != nil {
		slog.WarnContext(ctx, "Failed to listen (tailcat)", slogutil.Error(err))
		return err
	}

	// Startup (fetching a DERP map, picking a region) happens here, bounded
	// by ctx. A failure is retried by the supervisor, as for other listeners.
	listener, err := server.Listen(ctx, "tcp", ":"+strconv.Itoa(int(port)))
	if err != nil {
		tcLinks.serverFailed(err)
		slog.WarnContext(ctx, "Failed to listen (tailcat)", slogutil.Error(err))
		return err
	}
	defer listener.Close()

	tcLinks.serverStarted(server)

	t.running.Store(true)
	defer t.running.Store(false)

	// The tailcat address is deliberately not announced through discovery:
	// it carries the tunnel's pre-shared key, which is ours to hand out, and
	// is shared through the device identification dialog instead.
	slog.InfoContext(ctx, "Tailcat listener starting", "address", tailcatURI(server.TailcatAddr(), port))
	defer slog.InfoContext(ctx, "Tailcat listener shutting down")

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	acceptFailures := 0
	const maxAcceptFailures = 10

	for {
		conn, err := listener.Accept()
		if ctx.Err() != nil {
			if err == nil {
				conn.Close()
			}
			return nil
		}
		if err != nil {
			slog.WarnContext(ctx, "Failed to accept tailcat connection", slogutil.Error(err))

			acceptFailures++
			if acceptFailures > maxAcceptFailures {
				// Something seems permanently damaged, restart the listener.
				return err
			}
			continue
		}
		acceptFailures = 0

		tc := tls.Server(conn, t.tlsCfg)
		if err := tlsTimedHandshake(tc); err != nil {
			slog.WarnContext(ctx, "Failed TLS handshake (tailcat)", slogutil.Address(tc.RemoteAddr()), slogutil.Error(err))
			tc.Close()
			continue
		}

		select {
		case t.conns <- newInternalConn(tc, connTypeTailcatServer, false, t.cfg.Options().ConnectionPriorityTCPWAN):
		case <-ctx.Done():
			tc.Close()
			return nil
		}
	}
}

func (t *tailcatListener) URI() *url.URL {
	return t.uri
}

// WANAddresses and LANAddresses are empty on purpose. A tailcat address is
// not a listening address in the usual sense: it is a secret handed out
// through the device identification dialog, not announced to discovery
// servers or over the LAN.
func (t *tailcatListener) WANAddresses() []*url.URL {
	return nil
}

func (t *tailcatListener) LANAddresses() []*url.URL {
	return nil
}

func (t *tailcatListener) String() string {
	return t.uri.String()
}

func (t *tailcatListener) Factory() listenerFactory {
	return t.factory
}

func (*tailcatListener) NATType() string {
	return "unknown"
}

// active reports whether this listener is accepting connections.
func (t *tailcatListener) active() bool {
	return t.running.Load()
}

// listenPort returns the port inside the tunnel that this listener serves.
func (t *tailcatListener) listenPort() uint16 {
	port, err := tailcatPort(t.uri)
	if err != nil {
		return uint16(config.DefaultTCPPort)
	}
	return port
}

type tailcatListenerFactory struct{}

func (f *tailcatListenerFactory) New(uri *url.URL, cfg config.Wrapper, tlsCfg *tls.Config, conns chan internalConn, _ *nat.Service, _ *registry.Registry, _ *lanChecker) genericListener {
	l := &tailcatListener{
		uri:     fixupPort(uri, config.DefaultTCPPort),
		cfg:     cfg,
		tlsCfg:  tlsCfg,
		conns:   conns,
		factory: f,
	}
	l.ServiceWithError = svcutil.AsService(l.serve, l.String())
	return l
}

func (tailcatListenerFactory) Valid(_ config.Configuration) error {
	// Always valid
	return nil
}
