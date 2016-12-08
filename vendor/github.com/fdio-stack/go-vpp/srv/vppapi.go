package srv

/*
#cgo CFLAGS: -I/usr/local/include/libvpp_cgoclient
#cgo LDFLAGS: -lvpp_cgoclient
#include <vpp_client.h>
extern client_main_t cm;
*/
import "C"
import (
	"github.com/briandowns/spinner"
	"github.com/fdio-stack/go-vpp/srv/stats"

	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
	"unsafe"
)

type vppInterface_t struct {
	name        string
	sw_if_index int
	admin_up    bool
	ip_addr     string
}

type vppBridge_t struct {
	name          string
	bridge_id     int
	has_interface bool
}

var wg_vppclient sync.WaitGroup
var connect sync.Once
var vppIntfByName = make(map[string]*vppInterface_t)
var vppBridgeByName = make(map[string]*vppBridge_t)

//brecode - save interfaces added to bridge domain
//var vppIntfByBridge = make(map[int]*vppBridgeIntf_t)
var next_bdid = 1

/**
 ***************************************************************

 *** VPP BRIDGE DOMAIN

 ***************************************************************
 */

var rv_bridge int

//export gocallback_l2_bridge_reply
func gocallback_l2_bridge_reply(retval *C.int) {
	rv_bridge = ^0
	fmt.Printf("go: I'm the l2_bridge_reply callback. \n")
	if int(*retval) == 0 {
		rv_bridge = int(*retval)
	}
	wg_vppclient.Done()
}

func create_l2_bridge(bd_id int, cm *C.client_main_t) {
	wg_vppclient.Add(1)
	c_bd_id := C.int(bd_id)
	C.add_l2_bridge(c_bd_id, cm)
	fmt.Printf("go: Called l2_bridge\n")
	wg_vppclient.Wait()
	if rv_bridge == ^0 {
		fmt.Printf("\n **** bollocks\n")
		return // brecode - need to fix return value
	}
}

/**
 ***************************************************************

 *** VPP BRIDGE DOMAIN SET INTERFACE

 ***************************************************************
 */

var rv_bridge_set_interface int

//export gocallback_l2_bridge_set_interface_reply
func gocallback_l2_bridge_set_interface_reply(retval *C.int) {
	rv_bridge_set_interface = ^0
	fmt.Printf("go: I'm the l2_bridge_set_interface_reply callback. \n")
	if int(*retval) == 0 {
		rv_bridge_set_interface = int(*retval)
	}
	wg_vppclient.Done()
}

func vpp_set_interface_l2_bridge(bd_id int, intf int, cm *C.client_main_t) {
	wg_vppclient.Add(1)
	fmt.Printf("Vpp host-int with value:%d", intf)
	c_rx_if_index := C.int(intf)
	c_bd_id := C.int(bd_id)
	C.set_l2_bridge_interface(c_bd_id, &c_rx_if_index, cm)
	fmt.Printf("go: Called l2_bridge_set_interface\n")
	wg_vppclient.Wait()
	if rv_bridge_set_interface == ^0 {
		fmt.Printf("\n **** bollocks\n")
		return // brecode - need to fix return value
	}
}

/**
 ***************************************************************

 *** VPP INTERFACE

 ***************************************************************
 */

/**
 *** VPP INTERFACE (AF_PACKET)
 */

var af_packet_sw_if_index int

//export gocallback_af_packet_create_reply
func gocallback_af_packet_create_reply(retval *C.int, sw_if_index *C.int) {
	af_packet_sw_if_index = ^0
	fmt.Printf("go: af_packet_create_reply callback: retval = %d \n", *retval)
	if int(*retval) == 0 {
		af_packet_sw_if_index = int(*sw_if_index)
	}
	wg_vppclient.Done()
}

func vpp_add_af_packet_interface(intf string, cm *C.client_main_t) {
	wg_vppclient.Add(1)
	C.add_af_packet_interface(C.CString(intf), cm)
	wg_vppclient.Wait()
	if af_packet_sw_if_index == ^0 {
		fmt.Printf("\n **** bollocks\n")
		return
	}
	fmt.Printf("go: af_packet created with sw_if_index = %d for interface = %s\n", af_packet_sw_if_index, intf)

	vppInt := vppInterface_t{
		intf,
		af_packet_sw_if_index,
		false,
		""}

	vppIntfByName[intf] = &vppInt
}

/************** STATS ****************/

//export gocallback_vnet_summary_interface_counters
func gocallback_vnet_summary_interface_counters(num_records *C.int, records *C.vpp_interface_summary_counters_record_t) {

	// Timestamp for now is same for every record in batch so only retrieve and convert to GOLANG once
	ts := time.Unix(int64(records.timestamp.tv_sec), 0)

	// CounterName for now is same for every record in batch so only retrieve and convert to GOLANG once
	counter_name := C.GoString(records.counter_name)

	fmt.Printf("go: vnet_summary_interface_counters: counter_name = %s\n", counter_name)

	for i := 0; i < (int)(*num_records); i++ {
		//want to use the same struct and get it out of here and repack (as in dedup) in the stats handler
		var ifRecord stats.VppInterfaceStats_t

		//Set the key
		ifRecord.Key.Timestamp = ts
		ifRecord.Key.Sw_if_index = int(records.sw_if_index)

		if counter_name == "tx" {
			ifRecord.Packets_tx = int64(records.packet_counter)
			ifRecord.Bytes_tx = int64(records.byte_counter)
		} else if counter_name == "rx" {
			ifRecord.Packets_rx = int64(records.packet_counter)
			ifRecord.Bytes_rx = int64(records.byte_counter)
		} else {
			ifRecord.Bogus = int64(records.packet_counter)
		}

		//		fmt.Printf("ts: %v sw_if_index: %d counter_name: %s packets: %d bytes: %d\n", ts, records.sw_if_index, C.GoString(records.counter_name), records.packet_counter, records.byte_counter)

		//todo add errors
		stats.AddInterfaceRecord(ifRecord)
		records = records.next
	}
}

//export gocallback_vnet_interface_counters
func gocallback_vnet_interface_counters(num_records *C.int, records *C.vpp_interface_counters_record_t) {

	// Timestamp for now is same for every record in batch so only retrieve and convert to GOLANG once
	ts := time.Unix(int64(records.timestamp.tv_sec), 0)

	// CounterName for now is same for every record in batch so only retrieve and convert to GOLANG once
	counter_name := C.GoString(records.counter_name)

	for i := 0; i < (int)(*num_records); i++ {
		//want to use the same struct and get it out of here and repack (as in dedup) in the stats handler
		var ifRecord stats.VppInterfaceStats_t

		// Set the key
		ifRecord.Key.Timestamp = ts
		ifRecord.Key.Sw_if_index = int(records.sw_if_index)

		switch counter_name {
		default:
			fmt.Printf("gocallback_vnet_interface_counters doesn't know what to do with counter_name: %s\n", counter_name)
		case "drop":
			ifRecord.Drop = int64(records.counter)
			break
		case "punt":
			ifRecord.Punt = int64(records.counter)
			break
		case "ip4":
			ifRecord.Ip4 = int64(records.counter)
			break
		case "ip6":
			ifRecord.Ip6 = int64(records.counter)
			break
		case "rx_no_buf":
			ifRecord.Rx_no_buf = int64(records.counter)
			break
		case "rx_miss":
			ifRecord.Rx_miss = int64(records.counter)
			break
		case "rx_error":
			ifRecord.Rx_error = int64(records.counter)
			break
		case "tx_error_fifo_full":
			ifRecord.Tx_error_fifo_full = int64(records.counter)
			break
		case "bogus":
			ifRecord.Bogus = int64(records.counter)
			break
		}

		// ... and before someone asks "why not use Reflection"
		// a) don't be a weenie
		// b) prove its faster and more explicitly expressive than the above
		// c) see a)
		// d) would rather not rely on external libraries that much... cos ... this should be
		// re-written in C/C++
		//reflect.ValueOf(&ifRecord).Elem().FieldByName(counter_name).SetInt(int64(records.counter))

		//todo add errors
		stats.AddInterfaceRecord(ifRecord)
		records = records.next
	}
}

// Ingest records based on consumer focused key. In this case sw_if_index, rather than

func vpp_stats_enable_disable(enable_disable int, cm *C.client_main_t) {
	enable := C.int(enable_disable)
	C.stats_enable_disable(enable, cm)
}

/**
 *** VPP General interface functions - admin_up, ip_addr
 */

//export gocallback_add_del_address_reply
func gocallback_add_del_address_reply() {
	wg_vppclient.Done()
}

func vpp_add_del_interface_ip_address(enable bool, sw_if_index int, ipaddr uint32, length uint8, cm *C.client_main_t) {
	wg_vppclient.Add(1)
	var enable_disable C.int = 0
	if enable {
		enable_disable = 1
	}
	c_sw_if_index := C.int(sw_if_index)
	var c_ipaddr C.u32 = (C.u32)(ipaddr)
	var c_length C.u8 = (C.u8)(length)
	// defer C.free(unsafe.Pointer(c_ipaddr))
	// defer C.free(unsafe.Pointer(c_length))

	C.add_del_interface_address(enable_disable, &c_sw_if_index, &c_ipaddr, &c_length, cm)
	wg_vppclient.Wait()
}

//export gocallback_set_interface_flags
func gocallback_set_interface_flags(retval *C.int) {
	fmt.Printf("go: af_packet_create_reply callback: retval = %d \n", *retval)
	wg_vppclient.Done()
}

func vpp_set_vpp_interface_adminup(intf string, cm *C.client_main_t) {

	v, ok := vppIntfByName[intf]
	if !ok {
		fmt.Printf("%s not found in vppIntfByName\n", intf)
		return
	}
	wg_vppclient.Add(1)
	sw_if_index := C.int(v.sw_if_index)
	admin_up := C.int(1)
	fmt.Printf("Interface with index %d is up\n", v.sw_if_index)
	C.set_flags(&sw_if_index, &admin_up, cm)
	wg_vppclient.Wait()
	vppIntfByName[intf].admin_up = true
}

/**
  Connect and disconnect VPP
*/

//export gocallback_connect_to_vpp
func gocallback_connect_to_vpp(rcm *C.client_main_t) {
	C.cm = *rcm
	wg_vppclient.Done()
}

// Connects to VPP shared memory API queue client. client_main_t
// is declared in C header and allocated here. Freed in vpp_disconnect()
func vpp_connect(client_name string, cm *C.client_main_t) {
	wg_vppclient.Add(1)
	cs := C.CString(client_name)
	defer C.free(unsafe.Pointer(cs))

	cm.my_client_name = cs
	C.connect_to_vpp(cm)
	wg_vppclient.Wait()
}

// Notifies VPP of client disconnect and frees client_main_t pointer
func vpp_disconnect() {
	C.disconnect_from_vpp()
}

/***** GO WRAPPERS ****/

func add_interface_ip_address(intf string, ipaddr string, cm *C.client_main_t) {
	var ip4_asuint uint32
	var ip4_length uint8

	if v, present := vppIntfByName[intf]; present {
		if !v.admin_up {
			fmt.Printf("%s is not up ... fixing that now\n", intf)
			vpp_set_vpp_interface_adminup(intf, cm)
		}
	} else {
		fmt.Printf("Trying to add IP address to something that doesn't exist %s \n", intf)
		return
	}

	ip, _, _ := net.ParseCIDR(ipaddr)
	fmt.Printf("IP address: %+v\n", ip)
	ipAddress, ipNet, _ := net.ParseCIDR(ipaddr)
	ip4_asuint = binary.BigEndian.Uint32(ipAddress.To4())
	tmp_ip4_length, _ := ipNet.Mask.Size()
	ip4_length = (uint8)(tmp_ip4_length)

	vpp_add_del_interface_ip_address(true, vppIntfByName[intf].sw_if_index, ip4_asuint, ip4_length, cm)

	// Update local hash map
	vppIntfByName[intf].ip_addr = ipaddr
}

/***** Debugging funcs ********/

func dumpVppInterfaceMap() {
	fmt.Printf("vppIntfByName dump: Has %d members: \n", len(vppIntfByName))
	for _, v := range vppIntfByName {
		fmt.Printf("%+v\n", *v)
	}

}

func myspinner() {
	s := spinner.New(spinner.CharSets[34], 100*time.Millisecond) // Build our new spinner
	s.Start()                                                    // Start the spinner
	time.Sleep(5 * time.Second)                                  // Run for some time to simulate work
	s.Stop()
}

/************ PUBLIC *********************/

func VppConnect(name string) {
	//Please note that vpp_connect has a callback that updates global cm
	vpp_connect(name, &C.cm)
	var enable_stats int = 1
	vpp_stats_enable_disable(enable_stats, &C.cm)
}

func VppBridgeDomain(name string) int {
	bdid := next_bdid
	vppBridge := vppBridge_t{
		name, bdid, false}
	create_l2_bridge(bdid, &C.cm) // brecode - need to get a return value and check...
	vppBridgeByName[name] = &vppBridge
	next_bdid++
	return (bdid)
}

func VppAddInterface(veth string) {
	vpp_add_af_packet_interface(veth, &C.cm)
	//	dumpVppInterfaceMap()
}

func VppAddInterfaceIp(veth string, ip string) {
	add_interface_ip_address(veth, ip, &C.cm)
}

func VppInterfaceAdminUp(veth string) {
	vpp_set_vpp_interface_adminup(veth, &C.cm)
}

func VppInterfaceL2Bridge(name string, intf string) {
	fmt.Printf("The bridge id is: %d", vppBridgeByName[name].bridge_id)
	vpp_set_interface_l2_bridge(vppBridgeByName[name].bridge_id,
		vppIntfByName[intf].sw_if_index, &C.cm)
}

func VppDisconnect() {
	vpp_disconnect()
	stats.Close()
}

// /***************** MAIN ******************/
// func main() {

// 	/* This block loops until Ctrl-C is hit then disconnects */
// 	c := make(chan os.Signal, 1)
// 	signal.Notify(c, os.Interrupt)
// 	signal.Notify(c, syscall.SIGTERM)
// 	go func() {
// 		<-c
// 		vpp_disconnect()
// 		os.Exit(1)
// 	}()
// 	/* END clean up on SIGINT */

// 	/* If we have to sit around for stats, lets do something constructive */
// 	for {
// 	}
// }