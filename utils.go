// Copyright 2023 Wayback Archiver. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package proxier // import "github.com/wabarc/proxier"

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"

	"github.com/go-ini/ini"
)

func parseInterface(cfg *ini.File, device *DeviceConfig) error {
	sections, err := cfg.SectionsByName("Interface")
	if len(sections) != 1 || err != nil {
		return errors.New("one and only one [Interface] is expected")
	}
	section := sections[0]

	address, err := parseCIDRNetIP(section, "Address")
	if err != nil {
		return err
	}

	device.Address = address

	privKey, err := parseBase64KeyToHex(section, "PrivateKey")
	if err != nil {
		return err
	}
	device.PrivateKey = privKey

	dns, err := parseNetIP(section, "DNS")
	if err != nil {
		return err
	}
	device.DNS = dns

	if sectionKey, err := section.GetKey("MTU"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return err
		}
		device.MTU = value
	}

	return nil
}

func parsePeer(cfg *ini.File, peer *PeerConfig) error {
	section := cfg.Section("Peer")
	if section == nil {
		return errors.New("at least one [Peer] is expected")
	}

	decoded, err := parseBase64KeyToHex(section, "PublicKey")
	if err != nil {
		return err
	}
	peer.PublicKey = decoded

	if sectionKey, err := section.GetKey("PreSharedKey"); err == nil {
		value, err := encodeBase64ToHex(sectionKey.String())
		if err != nil {
			return err
		}
		peer.PreSharedKey = value
	}

	decoded, err = parseString(section, "Endpoint")
	if err != nil {
		return err
	}
	decoded, err = resolveIPPAndPort(decoded)
	if err != nil {
		return err
	}
	peer.Endpoint = decoded

	if sectionKey, err := section.GetKey("PersistentKeepalive"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return err
		}
		peer.KeepAlive = value
	}

	peer.AllowedIPs, err = parseAllowedIPs(section)
	if err != nil {
		return err
	}

	return nil
}

func parseCIDRNetIP(section *ini.Section, keyName string) ([]netip.Addr, error) {
	key := section.Key(keyName)
	if key == nil {
		return []netip.Addr{}, nil
	}

	var ips []netip.Addr
	for _, str := range key.StringsWithShadows(",") {
		prefix, err := netip.ParsePrefix(str)
		if err != nil {
			return nil, err
		}

		addr := prefix.Addr()
		if prefix.Bits() != addr.BitLen() {
			return nil, errors.New("interface address subnet should be /32 for IPv4 and /128 for IPv6")
		}

		ips = append(ips, addr)
	}
	return ips, nil
}

func parseBase64KeyToHex(section *ini.Section, keyName string) (string, error) {
	key, err := parseString(section, keyName)
	if err != nil {
		return "", err
	}
	result, err := encodeBase64ToHex(key)
	if err != nil {
		return result, err
	}

	return result, nil
}

func parseNetIP(section *ini.Section, keyName string) ([]netip.Addr, error) {
	key := section.Key(keyName)
	if key == nil {
		return []netip.Addr{}, nil
	}

	var ips []netip.Addr
	for _, str := range key.StringsWithShadows(",") {
		str = strings.TrimSpace(str)
		ip, err := netip.ParseAddr(str)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func parseString(section *ini.Section, keyName string) (string, error) {
	key := section.Key(strings.ToLower(keyName))
	if key == nil {
		return "", errors.New(keyName + " should not be empty")
	}
	return key.String(), nil
}

func encodeBase64ToHex(key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", errors.New("invalid base64 string: " + key)
	}
	if len(decoded) != 32 {
		return "", errors.New("key should be 32 bytes: " + key)
	}
	return hex.EncodeToString(decoded), nil
}

func resolveIPPAndPort(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}

	ip, err := resolveIP(host)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ip.String(), port), nil
}

func parseAllowedIPs(section *ini.Section) ([]netip.Prefix, error) {
	key := section.Key("AllowedIPs")
	if key == nil {
		return []netip.Prefix{}, nil
	}

	var ips []netip.Prefix
	for _, str := range key.StringsWithShadows(",") {
		prefix, err := netip.ParsePrefix(str)
		if err != nil {
			return nil, err
		}

		ips = append(ips, prefix)
	}
	return ips, nil
}

func resolveIP(ip string) (*net.IPAddr, error) {
	return net.ResolveIPAddr("ip", ip)
}
