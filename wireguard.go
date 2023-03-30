// Copyright 2023 Wayback Archiver. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package proxier // import "github.com/wabarc/proxier"

import (
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"

	"github.com/go-ini/ini"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// PeerConfig represents the configuration for a peer in a virtual private network.
type PeerConfig struct {
	AllowedIPs   []netip.Prefix
	PublicKey    string
	PreSharedKey string
	Endpoint     string
	KeepAlive    int
}

// DeviceConfig represents the configuration for a virtual network device.
type DeviceConfig struct {
	Address    []netip.Addr
	DNS        []netip.Addr
	Peer       PeerConfig
	PrivateKey string
	MTU        int
}

// ViaWireGuard changes the http client to use a WireGuard network for communication.
// It is a method of the Client struct that sets up a WireGuard connection using the provided io.Reader.
// The method returns nil, indicating that the connection setup was successful.
//
// Here's an example of a WireGuard configuration file, which you can use as a reference for creating your own configuration.
//
//	[Interface]
//	PrivateKey = <private key of this device>
//	Address = 10.0.0.2/24
//	DNS = 8.8.8.8
//
//	[Peer]
//	PublicKey = <public key of the server>
//	AllowedIPs = 0.0.0.0/0
//	Endpoint = <public IP address of the server>:51820
//	PersistentKeepalive = 25
func (c *Client) ViaWireGuard(r io.Reader) error {
	iniOpt := ini.LoadOptions{
		Insensitive:            true,
		AllowShadows:           true,
		AllowNonUniqueSections: true,
	}

	cfg, err := ini.LoadSources(iniOpt, r)
	if err != nil {
		return err
	}

	dev := &DeviceConfig{
		MTU: device.DefaultMTU,
	}

	root := cfg.Section("")
	wgConf, err := root.GetKey("WGConfig")
	wgCfg := cfg
	if err == nil {
		wgCfg, err = ini.LoadSources(iniOpt, wgConf.String())
		if err != nil {
			return err
		}
	}

	err = parseInterface(wgCfg, dev)
	if err != nil {
		return err
	}

	err = parsePeer(wgCfg, &dev.Peer)
	if err != nil {
		return err
	}

	client, err := newWireGuardClient(dev)
	if err != nil {
		return err
	}
	c.Client.Transport = client.Transport
	return nil
}

func newWireGuardClient(dev *DeviceConfig) (*http.Client, error) {
	tun, tnet, err := netstack.CreateNetTUN(dev.Address, dev.DNS, dev.MTU)
	if err != nil {
		return nil, err
	}

	pvk, pk := dev.PrivateKey, dev.Peer.PublicKey
	allowedIPs := []string{}
	for _, ip := range dev.Peer.AllowedIPs {
		allowedIPs = append(allowedIPs, ip.String())
	}
	if len(allowedIPs) == 0 {
		allowedIPs = []string{`0.0.0.0/0`}
	}

	format := `private_key=%s\npublic_key=%s\nallowed_ip=%s\nendpoint=%s`
	uapi := fmt.Sprintf(format, pvk, pk, strings.Join(allowedIPs, `,`), dev.Peer.Endpoint)
	nd := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))
	err = nd.IpcSet(uapi)
	if err != nil {
		return nil, err
	}
	err = nd.Up()
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: tnet.DialContext,
		},
	}

	return client, nil
}
