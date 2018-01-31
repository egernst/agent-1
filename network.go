//
// Copyright (c) 2017 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"

	pb "github.com/kata-containers/agent/protocols/grpc"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// Network fully describes a sandbox network with its interfaces, routes and dns
// related information.
type network struct {
	ifacesLock sync.Mutex
	ifaces     []*pb.Interface

	routesLock sync.Mutex
	routes     []*pb.Route

	dnsLock sync.Mutex
	dns     []string
}

////////////////
// Interfaces //
////////////////

func linkByHwAddr(netHandle *netlink.Handle, hwAddr string) (netlink.Link, error) {
	links, err := netHandle.LinkList()
	if err != nil {
		return nil, err
	}

	for _, link := range links {
		lAttrs := link.Attrs()
		if lAttrs == nil {
			continue
		}

		if lAttrs.HardwareAddr.String() == hwAddr {
			return link, nil
		}
	}

	return nil, fmt.Errorf("Could not find the link corresponding to HwAddr %q", hwAddr)
}

func updateLink(netHandle *netlink.Handle, link netlink.Link, iface *pb.Interface) error {

	// set the addresses
	for _, addr := range iface.IpAddresses {
		netlinkAddrStr := fmt.Sprintf("%s/%s", addr.Address, addr.Mask)

		netlinkAddr, err := netlink.ParseAddr(netlinkAddrStr)
		if err != nil {
			return fmt.Errorf("Could not parse %q: %v", netlinkAddrStr, err)
		}

		if err := netHandle.AddrAdd(link, netlinkAddr); err != nil {
			return fmt.Errorf("Could not add %s to interface %v: %v",
				netlinkAddrStr, link, err)
		}
	}

	// set the interface name
	if err := netHandle.LinkSetName(link, iface.Name); err != nil {
		return fmt.Errorf("Could not set name %s for interface %v: %v", iface.Name, link, err)
	}

	// set the interface MTU
	if err := netHandle.LinkSetMTU(link, int(iface.Mtu)); err != nil {
		return fmt.Errorf("Could not set MTU %d for interface %v: %v", iface.Mtu, link, err)
	}

	return nil
}

func (s *sandbox) addInterface(netHandle *netlink.Handle, iface *pb.Interface) (resultingIfc *pb.Interface, err error) {
	s.network.ifacesLock.Lock()
	defer s.network.ifacesLock.Unlock()

	if netHandle == nil {
		netHandle, err = netlink.NewHandle()
		if err != nil {
			return nil, err
		}
		defer netHandle.Delete()
	}

	if iface == nil {
		return nil, fmt.Errorf("Provided interface is nil")
	}

	hwAddr, err := net.ParseMAC(iface.HwAddr)
	if err != nil {
		return nil, err
	}

	link := &netlink.Device{
		LinkAttrs: netlink.LinkAttrs{
			MTU:          int(iface.Mtu),
			TxQLen:       -1,
			Name:         iface.Name,
			HardwareAddr: hwAddr,
		},
	}

	// Create the link.
	if err := netHandle.LinkAdd(link); err != nil {
		return nil, err
	}

	// Set the link up.
	if err := netHandle.LinkSetUp(link); err != nil {
		return iface, err
	}

	// Update sandbox interface list.
	s.network.ifaces = append(s.network.ifaces, iface)

	return iface, nil
}
func (s *sandbox) removeInterface(netHandle *netlink.Handle, iface *pb.Interface) (resultingIfc *pb.Interface, err error) {
	s.network.ifacesLock.Lock()
	defer s.network.ifacesLock.Unlock()

	if netHandle == nil {
		netHandle, err = netlink.NewHandle()
		if err != nil {
			return nil, err
		}
		defer netHandle.Delete()
	}

	// Find the interface by hardware address.
	link, err := linkByHwAddr(netHandle, iface.HwAddr)
	if err != nil {
		return nil, err
	}

	// Set the link down.
	if err := netHandle.LinkSetDown(link); err != nil {
		return iface, err
	}

	// Delete the link.
	if err := netHandle.LinkDel(link); err != nil {
		return iface, err
	}

	// Update sandbox interface list.
	for idx, sIface := range s.network.ifaces {
		if sIface.Name == iface.Name {
			s.network.ifaces = append(s.network.ifaces[:idx], s.network.ifaces[idx+1:]...)
			break
		}
	}

	return nil, nil
}

func (s *sandbox) updateInterface(netHandle *netlink.Handle, iface *pb.Interface) (resultingIfc *pb.Interface, err error) {
	s.network.ifacesLock.Lock()
	defer s.network.ifacesLock.Unlock()

	if netHandle == nil {
		netHandle, err = netlink.NewHandle()
		if err != nil {
			return nil, err
		}
		defer netHandle.Delete()
	}

	if iface == nil {
		return nil, fmt.Errorf("Provided interface is nil")
	}

	fieldLogger := agentLog.WithFields(logrus.Fields{
		"mac-address":    iface.HwAddr,
		"interface-name": iface.Device,
	})

	var link netlink.Link
	if iface.HwAddr != "" {
		fieldLogger.Info("Getting interface from MAC address")

		// Find the interface link from its hardware address.
		link, err = linkByHwAddr(netHandle, iface.HwAddr)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("Interface HwAddr empty")
	}

	fieldLogger.WithField("link", fmt.Sprintf("%+v", link)).Info("Link found")

	lAttrs := link.Attrs()
	if lAttrs != nil && (lAttrs.Flags&net.FlagUp) == net.FlagUp {
		// The link is up, makes sure we get it down before
		// doing any modification.
		err = netHandle.LinkSetDown(link)
		if err != nil {
			goto error_case
		}
	}

	err = updateLink(netHandle, link, iface)
	if err != nil {
		goto error_case
	}
	err = netHandle.LinkSetUp(link)

error_case:
	// in the event that an error occurred during the interface update, make sure we return
	// the resulting state instead of the requested state
	if err != nil {
		resultingIfc = getInterface(netHandle, link)
	} else {
		resultingIfc = iface
	}

	return resultingIfc, netHandle.LinkSetUp(link)
}

// getInterface will retrieve interface details from the provided link
func getInterface(netHandle *netlink.Handle, link netlink.Link) *pb.Interface {
	var ifc pb.Interface
	linkAttrs := link.Attrs()
	ifc.Name = linkAttrs.Name
	ifc.Mtu = uint64(linkAttrs.MTU)
	ifc.HwAddr = linkAttrs.HardwareAddr.String()

	addrs, _ := netHandle.AddrList(link, netlink.FAMILY_V4)
	for _, addr := range addrs {
		s := strings.Split(addr.String(), "/")

		m := pb.IpAddress{
			Address: s[0],
			Mask:    s[1],
		}
		ifc.IpAddresses = append(ifc.IpAddresses, &m)
	}

	return &ifc
}

////////////
// Routes //
////////////

func (s *sandbox) addRoute(netHandle *netlink.Handle, route *pb.Route) error {
	return s.updateRoute(netHandle, route, true)
}

func (s *sandbox) removeRoute(netHandle *netlink.Handle, route *pb.Route) error {
	return s.updateRoute(netHandle, route, false)
}

func (s *sandbox) updateRoute(netHandle *netlink.Handle, route *pb.Route, add bool) (err error) {
	s.network.routesLock.Lock()
	defer s.network.routesLock.Unlock()

	if netHandle == nil {
		netHandle, err = netlink.NewHandle()
		if err != nil {
			return err
		}
		defer netHandle.Delete()
	}

	if route == nil {
		return fmt.Errorf("Provided route is nil")
	}

	// Find link index from route's device name.
	link, err := netHandle.LinkByName(route.Device)
	if err != nil {
		return fmt.Errorf("Could not find link from device %s: %v", route.Device, err)
	}

	linkAttrs := link.Attrs()
	if linkAttrs == nil {
		return fmt.Errorf("Could not get link's attributes for device %s", route.Device)
	}

	var dst *net.IPNet
	if route.Dest != "default" {
		_, dst, err = net.ParseCIDR(route.Dest)
		if err != nil {
			return fmt.Errorf("Could not parse route destination %s: %v", route.Dest, err)
		}
	}

	netRoute := &netlink.Route{
		LinkIndex: linkAttrs.Index,
		Dst:       dst,
		Gw:        net.ParseIP(route.Gateway),
	}

	if add {
		if err := netHandle.RouteAdd(netRoute); err != nil {
			return fmt.Errorf("Could not add route dest(%s)/gw(%s)/dev(%s): %v",
				route.Dest, route.Gateway, route.Device, err)
		}

		// Add route to sandbox route list.
		s.network.routes = append(s.network.routes, route)
	} else {
		if err := netHandle.RouteDel(netRoute); err != nil {
			return fmt.Errorf("Could not remove route dest(%s)/gw(%s)/dev(%s): %v",
				route.Dest, route.Gateway, route.Device, err)
		}

		// Remove route from sandbox route list.
		for idx, sandboxRoute := range s.network.routes {
			if reflect.DeepEqual(sandboxRoute, route) {
				s.network.routes = append(s.network.routes[:idx], s.network.routes[idx+1:]...)
				break
			}
		}
	}

	return nil
}

/////////
// DNS //
/////////

func setupDNS(dns []string) error {
	return nil
}

func removeDNS(dns []string) error {
	return nil
}

////////////
// Global //
////////////

// Remove everything related to network.
func (s *sandbox) removeNetwork() error {
	netHandle, err := netlink.NewHandle()
	if err != nil {
		return err
	}
	defer netHandle.Delete()

	for _, route := range s.network.routes {
		if err := s.removeRoute(netHandle, route); err != nil {
			return fmt.Errorf("Could not remove network route %v: %v",
				route, err)
		}
	}

	for _, iface := range s.network.ifaces {
		if _, err := s.removeInterface(netHandle, iface); err != nil {
			return fmt.Errorf("Could not remove network interface %v: %v",
				iface, err)
		}
	}

	if err := removeDNS(s.network.dns); err != nil {
		return fmt.Errorf("Could not remove network DNS: %v", err)
	}

	return nil
}
