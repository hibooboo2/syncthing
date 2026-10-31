// Copyright (C) 2026 The Syncthing Authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package connections

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"

	"github.com/syncthing/syncthing/lib/config"
	"github.com/syncthing/syncthing/lib/discover"
	"github.com/syncthing/syncthing/lib/protocol"
)

func TestTailcatAddrStable(t *testing.T) {
	identity := tailcatIdentity{
		Key:          key.NewNode(),
		PresharedKey: tailcat.NewPresharedKey(),
		RegionID:     42,
	}

	first, err := tailcatAddr(identity)
	if err != nil {
		t.Fatal(err)
	}
	second, err := tailcatAddr(identity)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("tailcat address changed between calls: %q != %q", first, second)
	}

	info, err := tailcat.ParseAddr(first)
	if err != nil {
		t.Fatal(err)
	}
	if info.RegionID != identity.RegionID {
		t.Errorf("region ID is %v, want %v", info.RegionID, identity.RegionID)
	}
	if info.PresharedKey != identity.PresharedKey {
		t.Error("pre-shared key is not the persisted one")
	}
	if info.ServerPublic.NodePublic != identity.Key.Public() {
		t.Error("server public key is not the persisted one")
	}
}

func TestTailcatAddrNoRegion(t *testing.T) {
	identity := tailcatIdentity{
		Key:          key.NewNode(),
		PresharedKey: tailcat.NewPresharedKey(),
	}
	if _, err := tailcatAddr(identity); err == nil {
		t.Error("expected an error for an identity without a DERP region")
	}
}

func TestLoadTailcatIdentityRoundTrip(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.xml")

	want := tailcatIdentity{
		Key:          key.NewNode(),
		PresharedKey: tailcat.NewPresharedKey(),
		RegionID:     7,
	}
	if err := saveTailcatIdentity(filepath.Join(dir, tailcatIdentityFile), want); err != nil {
		t.Fatal(err)
	}

	got, path, err := loadTailcatIdentity(context.Background(), configPath)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, tailcatIdentityFile) {
		t.Errorf("identity path is %q", path)
	}
	if got.Key.Public() != want.Key.Public() {
		t.Error("key did not survive the round trip")
	}
	if got.PresharedKey != want.PresharedKey {
		t.Error("pre-shared key did not survive the round trip")
	}
	if got.RegionID != want.RegionID {
		t.Errorf("region ID is %v, want %v", got.RegionID, want.RegionID)
	}

	// The address derived from the loaded identity must be the same as the
	// one derived from the identity we saved, i.e. survive a restart.
	wantAddr, err := tailcatAddr(want)
	if err != nil {
		t.Fatal(err)
	}
	gotAddr, err := tailcatAddr(got)
	if err != nil {
		t.Fatal(err)
	}
	if gotAddr != wantAddr {
		t.Errorf("address changed across restart: %q != %q", gotAddr, wantAddr)
	}
}

type fakeFinder struct {
	addresses []string
	lookups   int
}

func (f *fakeFinder) Lookup(context.Context, protocol.DeviceID) ([]string, error) {
	f.lookups++
	return f.addresses, nil
}

func (*fakeFinder) Error() error                                     { return nil }
func (*fakeFinder) String() string                                   { return "fake" }
func (*fakeFinder) Cache() map[protocol.DeviceID]discover.CacheEntry { return nil }

func TestResolveDeviceAddrsTailcatOnly(t *testing.T) {
	finder := &fakeFinder{addresses: []string{"tcp://192.0.2.1:22000"}}
	svc := &service{discoverer: finder}

	cfg := config.DeviceConfiguration{
		DeviceID: protocol.EmptyDeviceID,
		Addresses: []string{
			"dynamic",
			"tcp://198.51.100.1:22000",
			"tailcat://tcexample:22000",
		},
	}

	got := svc.resolveDeviceAddrs(context.Background(), cfg)
	want := []string{"tailcat://tcexample:22000"}
	if !slices.Equal(got, want) {
		t.Errorf("resolved addresses are %v, want %v", got, want)
	}
	if finder.lookups != 0 {
		t.Errorf("discovery was queried %d times for a tailcat device", finder.lookups)
	}
}

func TestResolveDeviceAddrsDynamic(t *testing.T) {
	finder := &fakeFinder{addresses: []string{"tcp://192.0.2.1:22000"}}
	svc := &service{discoverer: finder}

	cfg := config.DeviceConfiguration{
		DeviceID:  protocol.EmptyDeviceID,
		Addresses: []string{"dynamic"},
	}

	got := svc.resolveDeviceAddrs(context.Background(), cfg)
	want := []string{"tcp://192.0.2.1:22000"}
	if !slices.Equal(got, want) {
		t.Errorf("resolved addresses are %v, want %v", got, want)
	}
	if finder.lookups != 1 {
		t.Errorf("discovery was queried %d times, want 1", finder.lookups)
	}
}
