//
// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"fmt"
	"net"
	"reflect"
	"sync"

	pb "github.com/kata-containers/agent/protocols/grpc"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const (
	emptyRouteAddr = "<nil>"
)

// Network fully describes a sandbox network with its interfaces, routes and dns
// related information.
type network struct {
	ifacesLock sync.Mutex
	ifaces     []*pb.Interface

	routesLock sync.Mutex
	routes     []*pb.Route

	dns []string
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

	// As a first step, clear out any existing addresses associated with the link:
	linkIPs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("Could not check initial addresses for the link: %v", err)
	}
	for _, linkIP := range linkIPs {
		if err := netlink.AddrDel(link, &linkIP); err != nil {
			return fmt.Errorf("Could not delete existing addresses: %v", err)
		}
	}

	// Set desired IP addresses:
	for _, addr := range iface.IPAddresses {
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

	// set the interface name:
	if err := netHandle.LinkSetName(link, iface.Name); err != nil {
		return fmt.Errorf("Could not set name %s for interface %v: %v", iface.Name, link, err)
	}

	// set the interface MTU:
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
		return nil, fmt.Errorf("removeInterface: %v", err)
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
			return nil, fmt.Errorf("updateInterface: %v", err)
		}
	} else {
		return nil, fmt.Errorf("Interface HwAddr empty")
	}

	fieldLogger.WithField("link", fmt.Sprintf("%+v", link)).Info("Link found")

	lAttrs := link.Attrs()
	if lAttrs != nil && (lAttrs.Flags&net.FlagUp) == net.FlagUp {
		// The link is up, makes sure we get it down before
		// doing any modification.
		if err := netHandle.LinkSetDown(link); err != nil {
			goto error_case
		}
	}

	err = updateLink(netHandle, link, iface)

error_case:
	// in the event that an error occurred during the interface update, make sure we return
	// the resulting state instead of the requested state
	if err != nil {
		resultingIfc = getInterface(netHandle, link)
	} else {
		resultingIfc = iface
	}

	//Put link back into up state
	retErr := netHandle.LinkSetUp(link)

	// If there was an error updating the interface, give that error precedence
	// over a potentional LinkSetUp error.
	if err != nil {
		retErr = err
	}

	return resultingIfc, retErr
}

// getInterface will retrieve interface details from the provided link
func getInterface(netHandle *netlink.Handle, link netlink.Link) *pb.Interface {
	var ifc pb.Interface
	linkAttrs := link.Attrs()
	ifc.Name = linkAttrs.Name
	ifc.Mtu = uint64(linkAttrs.MTU)
	ifc.HwAddr = linkAttrs.HardwareAddr.String()

	addrs, err := netHandle.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		agentLog.WithError(err).Error("getInterface() failed")
	}
	for _, addr := range addrs {
		netMask, _ := addr.Mask.Size()
		m := pb.IPAddress{
			Address: addr.IP.String(),
			Mask:    fmt.Sprintf("%d", netMask),
		}
		ifc.IPAddresses = append(ifc.IPAddresses, &m)
	}

	return &ifc
}

////////////
// Routes //
////////////

//updateRoutes will take requestedRoutes and create netlink routes, with a goal of creating a final
// state which matches the requested routes.  In doing this, preesxisting non-loopback routes will be
// removed from the network.  If an error occurs, this function returns the list of routes in
// gRPC-route format at the time of failure
func (s *sandbox) updateRoutes(netHandle *netlink.Handle, requestedRoutes *pb.Routes) (resultingRoutes *pb.Routes, err error) {

	if netHandle == nil {
		netHandle, err = netlink.NewHandle()
		if err != nil {
			return nil, err
		}
		defer netHandle.Delete()
	}

	//If we are returning an error, return the current routes on the system
	defer func() {
		if err != nil {
			resultingRoutes, _ = getCurrentRoutes(netHandle)
		}
	}()

	//
	// First things first, let's blow away all the existing routes.  The updateRoutes function
	// is designed to be declarative, so we will attempt to create state matching what is
	// requested, and in the event that we fail to do so, will return the error and final state.
	//

	initRouteList, err := netHandle.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	for _, initRoute := range initRouteList {
		// don't delete routes associated with lo:
		link, _ := netHandle.LinkByIndex(initRoute.LinkIndex)
		if link.Attrs().Name == "lo" || link.Attrs().Name == "::1" {
			continue
		}

		err = netHandle.RouteDel(&initRoute)
		if err != nil {
			//If there was an error deleting some of the initial routes,
			//return the error and the current routes on the system via
			//the defer function
			return
		}
	}

	//
	// Set each of the requested routes
	//
	// First make sure we set the interfaces initial routes, as otherwise we
	// won't be able to access the gateway
	for _, reqRoute := range requestedRoutes.Routes {
		if reqRoute.Gateway == "" {
			agentLog.Info("Inside setting a route... %+v", reqRoute)
			err = s.updateRoute(netHandle, reqRoute, true)
			if err != nil {
				agentLog.WithError(err).Error("update Route failed")
				//If there was an error setting the route, return the error
				//and the current routes on the system via the defer func
				return
			}

		}
	}
	// Take a second pass and apply the routes which include a gateway
	for _, reqRoute := range requestedRoutes.Routes {
		if reqRoute.Gateway != "" {
			agentLog.Info("gateway condition: Inside setting a route... %+v", reqRoute)
			err = s.updateRoute(netHandle, reqRoute, true)
			if err != nil {
				agentLog.WithError(err).Error("update Route failed")
				//If there was an error setting the route, return the
				//error and the current routes on the system via defer
				return
			}
		}
	}

	return requestedRoutes, err
}

//getCurrentRoutes is a helper to gather existing routes in gRPC protocol format
func getCurrentRoutes(netHandle *netlink.Handle) (*pb.Routes, error) {

	if netHandle == nil {
		netHandle, err := netlink.NewHandle()
		if err != nil {
			return nil, err
		}
		defer netHandle.Delete()
	}

	var routes pb.Routes

	//finalRouteList, err := netHandle.RouteList(nil, netlink.FAMILY_ALL)
	finalRouteList, err := netHandle.RouteListFiltered(netlink.FAMILY_ALL, nil, netlink.RT_FILTER_TABLE)
	if err != nil {
		return &routes, err
	}

	agentLog.WithFields(logrus.Fields{
		"routelist": finalRouteList,
	}).Info("dump of current route")

	for _, route := range finalRouteList {
		agentLog.Info("Looks like we 't hit the loop...")
		var r pb.Route
		if route.Dst != nil {
			r.Dest = route.Dst.String()
		}

		if route.Gw != nil {
			r.Gateway = route.Gw.String()
		}

		if route.Src != nil {
			r.Source = route.Src.String()
		}

		r.Scope = uint32(route.Scope)
		r.Table = int32(route.Table)

		link, err := netHandle.LinkByIndex(route.LinkIndex)
		if err != nil {
			return &routes, err
		}
		r.Device = link.Attrs().Name

		routes.Routes = append(routes.Routes, &r)
	}

	return &routes, nil
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
	if route.Dest == "default" || route.Dest == "" {
		dst = nil
	} else {
		_, dst, err = net.ParseCIDR(route.Dest)
		if err != nil {
			return fmt.Errorf("Could not parse route destination %s: %v", route.Dest, err)
		}
	}

	netRoute := &netlink.Route{
		LinkIndex: linkAttrs.Index,
		Dst:       dst,
		Src:       net.ParseIP(route.Source),
		Gw:        net.ParseIP(route.Gateway),
		Scope:     netlink.Scope(route.Scope),
		Table:     int(route.Table),
	}

	if add {
		if err := netHandle.RouteAdd(netRoute); err != nil {
			return fmt.Errorf("Could not add route %+v: %v", route, err)
		}

		// Add route to sandbox route list.
		s.network.routes = append(s.network.routes, route)
	} else {
		if err := netHandle.RouteDel(netRoute); err != nil {
			return fmt.Errorf("Could not remove route %+v: %v", route, err)
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
