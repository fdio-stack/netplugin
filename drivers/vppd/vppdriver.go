/***
Copyright 2017 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vppd

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/contiv/netplugin/core"
	"github.com/contiv/netplugin/drivers"
	"github.com/contiv/netplugin/netmaster/mastercfg"

	"github.com/ligato/cn-infra/logging"
	log "github.com/ligato/cn-infra/logging/logrus"

	agent_core "github.com/ligato/cn-infra/core"
	"github.com/ligato/vpp-agent/clientv1/linux/localclient"
	"github.com/ligato/vpp-agent/flavours/linuxlocal"
	vpp_acl "github.com/ligato/vpp-agent/plugins/defaultplugins/aclplugin/model/acl"
	vpp_if "github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/model/interfaces"
	vpp_l2 "github.com/ligato/vpp-agent/plugins/defaultplugins/l2plugin/model/l2"
	linux_if "github.com/ligato/vpp-agent/plugins/linuxplugin/model/interfaces"

	// TODO: move all communication with docker to the agent (i.e. create containerId-based namespace)
	dockerclient "github.com/docker/docker/client"
)

// EndpointConfig stores configuration for a given endpoint.
type EndpointConfig struct {
	vppVeth  *linux_if.LinuxInterfaces_Interface // VETH interface attached to AFPacket
	epVeth   *linux_if.LinuxInterfaces_Interface // VETH interface attached to the endpoint
	afpacket *vpp_if.Interfaces_Interface        // AFPacket interface
}

// NetworkConfig stores configuration for a given network.
type NetworkConfig struct {
	bd        *vpp_l2.BridgeDomains_BridgeDomain // Bridge domain
	vxlans    []*vpp_if.Interfaces_Interface     // List of all VXLAN tunnels
	endpoints map[string]EndpointConfig          // Endpoint ID -> Endpoint Config
}

// ACLConfig stores ACL configuration for a given network.
type ACLConfig struct {
	acl *vpp_acl.AccessLists_Acl // ACL
}

// VppDriverOperState carries operational state of the VppDriver.
type VppDriverOperState struct {
	core.CommonState

	// Cached currently applied configuration of networks and endpoints.
	LocalNetConfig      map[string]NetworkConfig // Network ID -> Network config
	localNetConfigMutex sync.Mutex
	LocalACLConfig      map[string]ACLConfig // Network ID -> ACL config
	localACLConfigMutex sync.Mutex
}

// Write the state
func (s *VppDriverOperState) Write() error {
	key := fmt.Sprintf(vppOperPath, s.ID)
	return s.StateDriver.WriteState(key, s, json.Marshal)
}

// Read the state given an ID.
func (s *VppDriverOperState) Read(id string) error {
	key := fmt.Sprintf(vppOperPath, id)
	return s.StateDriver.ReadState(key, s, json.Unmarshal)
}

// ReadAll reads all the state
func (s *VppDriverOperState) ReadAll() ([]core.State, error) {
	return s.StateDriver.ReadAllState(vppOperPathPrefix, s, json.Unmarshal)
}

// Clear removes the state.
func (s *VppDriverOperState) Clear() error {
	key := fmt.Sprintf(vppOperPath, s.ID)
	return s.StateDriver.ClearState(key)
}

// VppDriver holds the operational state of vpp driver
type VppDriver struct {
	lock sync.Mutex         // lock for modifying shared state
	oper VppDriverOperState // Oper state of the driver

	localIP    string   // Local IP address
	clusterIPS []string // Local cluster IP address

	vppAgent *agent_core.Agent // VPP agent

	// TODO: remove once agent supports containerId-based namespaces
	dockerClient *dockerclient.Client
}

// Init initializes the VPP driver with VPP agent.
func (d *VppDriver) Init(info *core.InstanceInfo) error {

	log.SetOutput(os.Stdout)
	log.SetLevel(logging.DebugLevel)

	if info == nil || info.StateDriver == nil {
		return core.Errorf("Invalid arguments. instance-info: %+v", info)
	}
	d.oper.StateDriver = info.StateDriver
	d.localIP = info.VtepIP

	// restore the driver's runtime state if it exists
	err := d.oper.Read(info.HostLabel)
	if core.ErrIfKeyExists(err) != nil {
		log.Errorf("Failed to read driver oper state for key %q. Error: %s",
			info.HostLabel, err)
		return err
	} else if err != nil {
		// create the oper state as it is first time start up
		d.oper.ID = info.HostLabel

		d.oper.LocalNetConfig = make(map[string]NetworkConfig)

		// write the oper
		err = d.oper.Write()
		if err != nil {
			return err
		}
	}

	// make sure LocalNetConfig exists
	if d.oper.LocalNetConfig == nil {
		d.oper.LocalNetConfig = make(map[string]NetworkConfig)
		// write the oper
		err = d.oper.Write()
		if err != nil {
			return err
		}
	}

	log.Infof("Initializing vppdriver")

	d.dockerClient, err = dockerclient.NewClient("unix:///var/run/docker.sock", "", nil, nil)
	if err != nil {
		log.Fatalf("Unable to connect to docker. Error %v", err)
		return err
	}

	flavour := linuxlocal.Flavour{}
	d.vppAgent = agent_core.NewAgent(log.StandardLogger(), 15*time.Second, flavour.Plugins()...)

	err = d.vppAgent.Start()
	if err != nil {
		log.Fatalf("Error starting VPP agent, Err: %v", err)
		return err
	}

	return nil
}

// Deinit closes the driver. Primarily it stops the associated VPP agent.
func (d *VppDriver) Deinit() {
	log.Infof("Cleaning up vppdriver")

	err := d.vppAgent.Stop()
	if err != nil {
		log.Warnf("Error stopping VPP agent, Err: '%v'", err)
	}

	err = d.dockerClient.Close()
	if err != nil {
		log.Warnf("Error closing docker client, Err: '%v'", err)
	}
}

// CreateNetwork creates a bridge domain network for a given ID in VPP
// We get the Tenant/vrf and network/subnet info from contiv in this API
func (d *VppDriver) CreateNetwork(id string) error {
	cfgNw := mastercfg.CfgNetworkState{}
	cfgNw.StateDriver = d.oper.StateDriver
	err := cfgNw.Read(id)
	if err != nil {
		log.Errorf("Failed to read network id='%s'", id)
		return err
	}

	d.oper.localNetConfigMutex.Lock()
	_, exists := d.oper.LocalNetConfig[id]
	d.oper.localNetConfigMutex.Unlock()
	if exists {
		err = fmt.Errorf("Network id='%s' is already configured", id)
		log.Error(err.Error())
		return err
	}

	log.Infof("Create network id='%s', config='%+v'", id, cfgNw)

	netcfg := NetworkConfig{}
	// bridge domain
	netcfg.bd = &vpp_l2.BridgeDomains_BridgeDomain{
		Name:                "bd-" + id,
		Flood:               true,
		UnknownUnicastFlood: true,
		Forward:             true,
		Learn:               true,
		ArpTermination:      false,
		MacAge:              0,
		Interfaces:          []*vpp_l2.BridgeDomains_BridgeDomain_Interfaces{},
	}

	// Create VXLAN tunnels between all the nodes of the cluster
	netcfg.vxlans = []*vpp_if.Interfaces_Interface{}
	for i, nodeIP := range d.clusterIPS {
		if nodeIP != d.localIP {
			vxlanName := fmt.Sprintf("vxlan-%s-%d", id, i)
			netcfg.vxlans = append(netcfg.vxlans,
				&vpp_if.Interfaces_Interface{
					Name:    vxlanName,
					Type:    vpp_if.InterfaceType_VXLAN_TUNNEL,
					Enabled: true,
					Vxlan: &vpp_if.Interfaces_Interface_Vxlan{
						SrcAddress: d.localIP,
						DstAddress: nodeIP,
					},
				})
			netcfg.bd.Interfaces = append(netcfg.bd.Interfaces,
				&vpp_l2.BridgeDomains_BridgeDomain_Interfaces{
					Name: vxlanName,
					BridgedVirtualInterface: false,
					SplitHorizonGroup:       1,
				})
		}
	}

	// Prepare map for the endpoints
	netcfg.endpoints = make(map[string]EndpointConfig)

	log.Infof("Network config: %v", netcfg)

	// Apply all changes
	putReq := localclient.DataChangeRequest(vppDriverID).Put()
	putReq.BD(netcfg.bd)
	for _, vxlan := range netcfg.vxlans {
		putReq.VppInterface(vxlan)
	}
	err = putReq.Send().ReceiveReply()
	if err != nil {
		log.Errorf("Failed to create network id='%s', Err: %v", id, err)
		return err
	}

	// Store the network configuration
	d.oper.localNetConfigMutex.Lock()
	d.oper.LocalNetConfig[id] = netcfg
	d.oper.localNetConfigMutex.Unlock()

	return nil
}

// DeleteNetwork deletes a network for a given ID from VPP
func (d *VppDriver) DeleteNetwork(id, subnet, nwType, encap string, pktTag, extPktTag int, gateway string, tenant string) error {
	log.Infof("Delete network id='%s'", id)

	d.oper.localNetConfigMutex.Lock()
	defer d.oper.localNetConfigMutex.Unlock()
	netcfg, exists := d.oper.LocalNetConfig[id]
	if !exists {
		err := fmt.Errorf("Network id='%s' is not configured", id)
		log.Error(err.Error())
		return err
	}

	deleteReq := localclient.DataChangeRequest(vppDriverID).Delete()
	for _, vxlan := range netcfg.vxlans {
		deleteReq.VppInterface(vxlan.Name)
	}
	deleteReq.BD(netcfg.bd.Name)

	// TODO: should we also remove all attached endpoints?

	err := deleteReq.Send().ReceiveReply()
	if err != nil {
		log.Errorf("Failed to delete network id='%s', Err: %v", id, err)
		return err
	}

	delete(d.oper.LocalNetConfig, id)
	return nil
}

// CreateEndpoint creates an endpoint for a given ID.
func (d *VppDriver) CreateEndpoint(id string) error {
	log.Infof("Create endpoint with id: %s", id)

	cfgEp := &mastercfg.CfgEndpointState{}
	cfgEp.StateDriver = d.oper.StateDriver
	err := cfgEp.Read(id)
	if err != nil {
		log.Errorf("Unable to get EpState for id: %s. Err: %v", id, err)
		return err
	}

	/*
		cinfo, err := d.dockerClient.ContainerInspect(context.Background(), cfgEp.ContainerID)
		if err != nil {
			log.Fatalf("Error getting container info for endpoint id: %s. Err: %v", id, err)
			return err
		}
	*/

	vppVethName := cfgEp.EndpointID[:9]
	epVethName := "veth-" + vppVethName
	afPacketName := "afpacket-" + vppVethName
	epcfg := EndpointConfig{}

	epcfg.vppVeth = &linux_if.LinuxInterfaces_Interface{
		Name:    vppVethName,
		Type:    linux_if.LinuxInterfaces_VETH,
		Enabled: true,
		Veth: &linux_if.LinuxInterfaces_Interface_Veth{
			PeerIfName: epVethName,
		},
	}

	epcfg.epVeth = &linux_if.LinuxInterfaces_Interface{
		Name:    epVethName,
		Type:    linux_if.LinuxInterfaces_VETH,
		Enabled: true,
		Veth: &linux_if.LinuxInterfaces_Interface_Veth{
			PeerIfName: vppVethName,
		},
		IpAddresses: []string{cfgEp.IPAddress},
		PhysAddress: cfgEp.MacAddress,
		// TODO: this should be something like Namespace_CONTAINER_REF_NS
		/*		Namespace: &linux_if.LinuxInterfaces_Interface_Namespace{
					Type: linux_if.LinuxInterfaces_Interface_Namespace_PID_REF_NS,
					Pid:  uint32(cinfo.State.Pid),
				},
		*/
	}

	epcfg.afpacket = &vpp_if.Interfaces_Interface{
		Name:    afPacketName,
		Type:    vpp_if.InterfaceType_AF_PACKET_INTERFACE,
		Enabled: true,
		Afpacket: &vpp_if.Interfaces_Interface_Afpacket{
			HostIfName: vppVethName,
		},
	}

	log.Infof("Endpoint config: %v", epcfg)

	d.oper.localNetConfigMutex.Lock()
	netcfg, netExists := d.oper.LocalNetConfig[cfgEp.NetID]
	if !netExists {
		d.oper.localNetConfigMutex.Unlock()
		err := fmt.Errorf("Network id='%s' is not configured", id)
		log.Error(err.Error())
		return err
	}

	_, epExists := netcfg.endpoints[cfgEp.ID]
	if epExists {
		d.oper.localNetConfigMutex.Unlock()
		err := fmt.Errorf("Endpoint id='%s' is already configured", id)
		log.Error(err.Error())
		return err
	}

	netcfg.bd.Interfaces = append(netcfg.bd.Interfaces,
		&vpp_l2.BridgeDomains_BridgeDomain_Interfaces{
			Name: afPacketName,
			BridgedVirtualInterface: false,
		})

	err = localclient.DataChangeRequest(vppDriverID).
		Put().
		BD(netcfg.bd).
		LinuxInterface(epcfg.vppVeth).
		LinuxInterface(epcfg.epVeth).
		VppInterface(epcfg.afpacket).
		Send().
		ReceiveReply()
	if err != nil {
		d.oper.localNetConfigMutex.Unlock()
		log.Errorf("Failed to create endpoint id='%s', Err: %v", id, err)
		return err
	}

	// Store the endpoint configuration
	netcfg.endpoints[id] = epcfg
	d.oper.localNetConfigMutex.Unlock()

	// Save the oper state
	operEp := &drivers.OperEndpointState{
		NetID:       cfgEp.NetID,
		EndpointID:  cfgEp.EndpointID,
		ServiceName: cfgEp.ServiceName,
		IPAddress:   cfgEp.IPAddress,
		MacAddress:  cfgEp.MacAddress,
		IntfName:    cfgEp.IntfName,
		HomingHost:  cfgEp.HomingHost,
		PortName:    epVethName,
	}

	operEp.StateDriver = d.oper.StateDriver
	operEp.ID = id
	err = operEp.Write()
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			operEp.Clear()
		}
	}()
	return nil
}

//UpdateEndpointGroup is not implemented.
func (d *VppDriver) UpdateEndpointGroup(id string) error {
	log.Infof("Not implemented")
	return nil
}

// DeleteEndpoint deletes endpoint with a given ID.
func (d *VppDriver) DeleteEndpoint(id string) error {
	epOper := drivers.OperEndpointState{}
	epOper.StateDriver = d.oper.StateDriver
	err := epOper.Read(id)
	if err != nil {
		return err
	}
	defer func() {
		epOper.Clear()
	}()

	cfgEp := &mastercfg.CfgEndpointState{}
	cfgEp.StateDriver = d.oper.StateDriver
	err = cfgEp.Read(id)
	if err != nil {
		log.Errorf("Unable to get EpState for id: %s. Err: %v", id, err)
		return err
	}

	d.oper.localNetConfigMutex.Lock()
	defer d.oper.localNetConfigMutex.Unlock()
	netcfg, netExists := d.oper.LocalNetConfig[cfgEp.NetID]
	if !netExists {
		err := fmt.Errorf("Network id='%s' is not configured", id)
		log.Error(err.Error())
		return err
	}

	epcfg, epExists := netcfg.endpoints[cfgEp.ID]
	if !epExists {
		err := fmt.Errorf("Endpoint id='%s' is not configured", id)
		log.Error(err.Error())
		return err
	}

	// Remove the associated afpacket interface from the bridge domain
	origBfIfs := netcfg.bd.Interfaces
	filteredBdIfs := []*vpp_l2.BridgeDomains_BridgeDomain_Interfaces{}
	for _, bdIf := range origBfIfs {
		if bdIf.Name != epcfg.afpacket.Name {
			filteredBdIfs = append(filteredBdIfs, bdIf)
		}
	}
	netcfg.bd.Interfaces = filteredBdIfs

	err = localclient.DataChangeRequest(vppDriverID).
		Put().
		BD(netcfg.bd).
		Delete().
		VppInterface(epcfg.afpacket.Name).
		LinuxInterface(epcfg.vppVeth.Name).
		LinuxInterface(epcfg.epVeth.Name).
		Send().ReceiveReply()
	if err != nil {
		netcfg.bd.Interfaces = origBfIfs
		log.Errorf("Failed to delete endpoint id='%s', Err: %v", id, err)
		return err
	}

	delete(netcfg.endpoints, id)
	return nil
}

// CreateRemoteEndpoint is not implemented.
func (d *VppDriver) CreateRemoteEndpoint(id string) error {
	log.Infof("Not implemented")
	return nil
}

// DeleteRemoteEndpoint is not implemented.
func (d *VppDriver) DeleteRemoteEndpoint(id string) (err error) {
	log.Infof("Not implemented")
	return nil
}

// CreateHostAccPort is not implemented.
func (d *VppDriver) CreateHostAccPort(id, a string, nw int) (string, error) {
	log.Infof("Not implemented")
	return "", nil
}

// DeleteHostAccPort is not implemented.
func (d *VppDriver) DeleteHostAccPort(id string) (err error) {
	log.Infof("Not implemented")
	return nil
}

// AddPeerHost is not implemented.
func (d *VppDriver) AddPeerHost(node core.ServiceInfo) error {
	// Nothing to do if this is our own IP
	if node.HostAddr == d.localIP {
		return nil
	}

	log.Infof("CreatePeerHost for %+v", node)

	// Add the VTEP to the clusterIPS
	d.clusterIPS = append(d.clusterIPS, node.HostAddr)
	return nil
}

// DeletePeerHost is not implemented.
func (d *VppDriver) DeletePeerHost(node core.ServiceInfo) error {
	log.Infof("Not implemented")
	return nil
}

// AddMaster is not implemented
func (d *VppDriver) AddMaster(node core.ServiceInfo) error {
	log.Infof("Not implemented")
	return nil
}

// DeleteMaster is not implemented
func (d *VppDriver) DeleteMaster(node core.ServiceInfo) error {
	log.Infof("Not implemented")
	return nil
}

// AddBgp is not implemented.
func (d *VppDriver) AddBgp(id string) (err error) {
	log.Infof("Not implemented")
	return nil
}

// DeleteBgp is not implemented.
func (d *VppDriver) DeleteBgp(id string) (err error) {
	log.Infof("Not implemented")
	return nil
}

// AddSvcSpec is not implemented.
func (d *VppDriver) AddSvcSpec(svcName string, spec *core.ServiceSpec) error {
	log.Infof("Not implemented")
	return nil
}

// DelSvcSpec is not implemented.
func (d *VppDriver) DelSvcSpec(svcName string, spec *core.ServiceSpec) error {
	log.Infof("Not implemented")
	return nil
}

// SvcProviderUpdate is not implemented.
func (d *VppDriver) SvcProviderUpdate(svcName string, providers []string) {
}

// GetEndpointStats is not implemented
func (d *VppDriver) GetEndpointStats() ([]byte, error) {
	log.Infof("Not implemented")
	return []byte{}, nil
}

// InspectState is not implemented
func (d *VppDriver) InspectState() ([]byte, error) {
	log.Infof("Not implemented")
	return []byte{}, nil
}

// InspectBgp is not implemented
func (d *VppDriver) InspectBgp() ([]byte, error) {
	log.Infof("Not implemented")
	return []byte{}, nil
}

// GlobalConfigUpdate is not implemented
func (d *VppDriver) GlobalConfigUpdate(inst core.InstanceInfo) error {
	log.Infof("Not implemented")
	return nil
}

// InspectNameserver is not implemented
func (d *VppDriver) InspectNameserver() ([]byte, error) {
	log.Infof("Not implemented")
	return []byte{}, nil
}

// AddPolicyRule is not implemented
func (d *VppDriver) AddPolicyRule(id string) error {
	ruleCfg := &mastercfg.CfgPolicyRule{}
	ruleCfg.StateDriver = d.oper.StateDriver
	err := ruleCfg.Read(id)
	if err != nil {
		log.Errorf("Failed to read ruleCfg \n")
		return err
	}

	d.oper.localACLConfigMutex.Lock()
	_, exists := d.oper.LocalACLConfig[id]
	d.oper.localACLConfigMutex.Unlock()
	if exists {
		err = fmt.Errorf("Network id='%s' is already configured", id)
		log.Error(err.Error())
		return err
	}

	vppRule := &ruleCfg.OfnetPolicyRule
	aclcfg := ACLConfig{}

	// Action rule to be VPP specific
	if vppRule.Action == "allow" {
		aclcfg.acl = &vpp_acl.AccessLists_Acl{
			Rules: []*vpp_acl.AccessLists_Acl_Rule{},
		}
		aclcfg.acl.Rules = append(aclcfg.acl.Rules,
			&vpp_acl.AccessLists_Acl_Rule{
				Actions: &vpp_acl.AccessLists_Acl_Rule_Actions{
					AclAction: vpp_acl.AclAction_PERMIT,
				},
			},
		)
	} else if vppRule.Action == "deny" {
		aclcfg.acl = &vpp_acl.AccessLists_Acl{
			Rules: []*vpp_acl.AccessLists_Acl_Rule{},
		}
		aclcfg.acl.Rules = append(aclcfg.acl.Rules,
			&vpp_acl.AccessLists_Acl_Rule{
				Actions: &vpp_acl.AccessLists_Acl_Rule_Actions{
					AclAction: vpp_acl.AclAction_DENY,
				},
			},
		)
	}

	// Src/DstNetwork choice based on protocol
	if vppRule.IpProtocol == 6 {
		aclcfg.acl.Rules = append(aclcfg.acl.Rules,
			&vpp_acl.AccessLists_Acl_Rule{
				Matches: &vpp_acl.AccessLists_Acl_Rule_Matches{
					IpRule: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule{
						Ip: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Ip{
							DestinationNetwork: vppRule.DstIpAddr,
							SourceNetwork:      vppRule.SrcIpAddr,
						},
						Tcp: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Tcp{
							DestinationPortRange: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Tcp_DestinationPortRange{
								LowerPort: uint32(vppRule.DstPort),
								UpperPort: uint32(vppRule.DstPort),
							},
							SourcePortRange: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Tcp_SourcePortRange{
								LowerPort: uint32(vppRule.DstPort),
								UpperPort: uint32(vppRule.DstPort),
							},
						},
					},
				},
			},
		)
	} else if vppRule.IpProtocol == 17 {
		aclcfg.acl.Rules = append(aclcfg.acl.Rules,
			&vpp_acl.AccessLists_Acl_Rule{
				Matches: &vpp_acl.AccessLists_Acl_Rule_Matches{
					IpRule: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule{
						Ip: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Ip{
							DestinationNetwork: vppRule.DstIpAddr,
							SourceNetwork:      vppRule.SrcIpAddr,
						},
						Udp: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Udp{
							DestinationPortRange: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Udp_DestinationPortRange{
								LowerPort: uint32(vppRule.DstPort),
								UpperPort: uint32(vppRule.DstPort),
							},
							SourcePortRange: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Udp_SourcePortRange{
								LowerPort: uint32(vppRule.DstPort),
								UpperPort: uint32(vppRule.DstPort),
							},
						},
					},
				},
			})
	} else {
		aclcfg.acl.Rules = append(aclcfg.acl.Rules,
			&vpp_acl.AccessLists_Acl_Rule{
				Matches: &vpp_acl.AccessLists_Acl_Rule_Matches{
					IpRule: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule{
						Ip: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Ip{
							DestinationNetwork: vppRule.DstIpAddr,
							SourceNetwork:      vppRule.SrcIpAddr,
						},
					},
				},
			},
		)
	}
	log.Infof("ACL config: %v", aclcfg)

	err = localclient.DataChangeRequest(vppDriverID).
		Put().
		ACL(aclcfg.acl).
		Send().
		ReceiveReply()

	if err != nil {
		log.Errorf("Failed to create network id='%s', Err: %v", id, err)
		return err
	}

	// Store the network configuration
	d.oper.localACLConfigMutex.Lock()
	d.oper.LocalACLConfig[id] = aclcfg
	d.oper.localACLConfigMutex.Unlock()
	return nil
}

// DelPolicyRule is not implemented
func (d *VppDriver) DelPolicyRule(id string) error {
	log.Infof("Not implemented")
	return nil
}
