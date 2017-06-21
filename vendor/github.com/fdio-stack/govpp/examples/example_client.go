// Example VPP management application that exercises the govpp API on real-world use-cases.
package main

// Generates Go bindings for all VPP APIs located in the json directory.
//go:generate binapi_generator --input-dir=bin_api --output-dir=bin_api

import (
	"fmt"
	"net"
	"os"

	"os/signal"

	"github.com/fdio-stack/govpp"
	"github.com/fdio-stack/govpp/api"
	"github.com/fdio-stack/govpp/api/ifcounters"
	"github.com/fdio-stack/govpp/core/bin_api/vpe"
	"github.com/fdio-stack/govpp/examples/bin_api/acl"
	"github.com/fdio-stack/govpp/examples/bin_api/interfaces"
	"github.com/fdio-stack/govpp/examples/bin_api/tap"
)

func main() {
	fmt.Println("Starting example VPP client...")

	// connect to VPP and create an API channel that will be used in the examples
	conn, _ := govpp.Connect()
	defer conn.Disconnect()

	ch, _ := conn.NewAPIChannel()
	defer ch.Close()

	// check whether the VPP supports our version of some messages
	compatibilityCheck(ch)

	// individual examples
	aclVersion(ch)
	aclConfig(ch)
	aclDump(ch)

	tapConnect(ch)

	interfaceDump(ch)
	interfaceNotifications(ch)

	//interfaceCounters(ch)
}

// compatibilityCheck shows how an management application can check whether generated API messages are
// compatible with the version of VPP which the library is connected to.
func compatibilityCheck(ch *api.Channel) {
	err := ch.CheckMessageCompatibility(
		&interfaces.SwInterfaceDump{},
		&interfaces.SwInterfaceDetails{},
	)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// aclVersion is the simplest API example - one empty request message and one reply message.
func aclVersion(ch *api.Channel) {
	req := &acl.ACLPluginGetVersion{}
	reply := &acl.ACLPluginGetVersionReply{}

	err := ch.SendRequest(req).ReceiveReply(reply)

	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("%+v\n", reply)
	}
}

// aclConfig is another simple API example - in this case, the request contains structured data.
func aclConfig(ch *api.Channel) {
	req := &acl.ACLAddReplace{
		ACLIndex: ^uint32(0),
		Tag:      []byte("access list 1"),
		R: []acl.ACLRule{
			{
				IsPermit:       1,
				SrcIPAddr:      net.ParseIP("10.0.0.0").To4(),
				SrcIPPrefixLen: 8,
				DstIPAddr:      net.ParseIP("192.168.1.0").To4(),
				DstIPPrefixLen: 24,
				Proto:          6,
			},
			{
				IsPermit:       1,
				SrcIPAddr:      net.ParseIP("8.8.8.8").To4(),
				SrcIPPrefixLen: 32,
				DstIPAddr:      net.ParseIP("172.16.0.0").To4(),
				DstIPPrefixLen: 16,
				Proto:          6,
			},
		},
	}
	reply := &acl.ACLAddReplaceReply{}

	err := ch.SendRequest(req).ReceiveReply(reply)

	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("%+v\n", reply)
	}
}

// aclDump shows an example where SendRequest and ReceiveReply are not chained together.
func aclDump(ch *api.Channel) {
	req := &acl.ACLDump{}
	reply := &acl.ACLDetails{}

	reqCtx := ch.SendRequest(req)
	err := reqCtx.ReceiveReply(reply)

	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("%+v\n", reply)
	}
}

// tapConnect example shows how the Go channels in the API channel can be accessed directly instead
// of using SendRequest and ReceiveReply wrappers.
func tapConnect(ch *api.Channel) {
	req := &tap.TapConnect{
		TapName:      []byte("testtap"),
		UseRandomMac: 1,
	}

	// send the request to the request go channel
	ch.ReqChan <- &api.VppRequest{Message: req}

	// receive a reply from the reply go channel
	vppReply := <-ch.ReplyChan
	if vppReply.Error != nil {
		fmt.Println("Error:", vppReply.Error)
		return
	}

	// decode the message
	reply := &tap.TapConnectReply{}
	err := ch.MsgDecoder.DecodeMsg(vppReply.Data, reply)

	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("%+v\n", reply)
	}
}

// interfaceDump shows an example of multipart request (multiple replies are expected).
func interfaceDump(ch *api.Channel) {
	req := &interfaces.SwInterfaceDump{}
	reqCtx := ch.SendMultiRequest(req)

	for {
		msg := &interfaces.SwInterfaceDetails{}
		stop, err := reqCtx.ReceiveReply(msg)
		if stop {
			break // break out of the loop
		}
		if err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Printf("%+v\n", msg)
	}
}

// interfaceNotifications shows the usage of notification API. Note that for notifications,
// you are supposed to create your own Go channel with your preferred buffer size. If the channel's
// buffer is full, the notifications will not be delivered into it.
func interfaceNotifications(ch *api.Channel) {
	// subscribe for specific notification message
	notifChan := make(chan api.Message, 100)
	subs, _ := ch.SubscribeNotification(notifChan, interfaces.NewSwInterfaceSetFlags)

	// enable interface events in VPP
	ch.SendRequest(&interfaces.WantInterfaceEvents{
		Pid:           uint32(os.Getpid()),
		EnableDisable: 1,
	}).ReceiveReply(&interfaces.WantInterfaceEventsReply{})

	// generate some events in VPP
	ch.SendRequest(&interfaces.SwInterfaceSetFlags{
		SwIfIndex:   0,
		AdminUpDown: 0,
	}).ReceiveReply(&interfaces.SwInterfaceSetFlagsReply{})
	ch.SendRequest(&interfaces.SwInterfaceSetFlags{
		SwIfIndex:   0,
		AdminUpDown: 1,
	}).ReceiveReply(&interfaces.SwInterfaceSetFlagsReply{})

	// receive one notification
	notif := (<-notifChan).(*interfaces.SwInterfaceSetFlags)
	fmt.Printf("%+v\n", notif)

	// unsubscribe from delivery of the notifications
	ch.UnsubscribeNotification(subs)
}

// interfaceCounters is an example of using notification API to periodically retrieve interface statistics.
// The ifcounters package contains the API that can be used to decode the strange VnetInterfaceCounters message.
func interfaceCounters(ch *api.Channel) {
	// subscribe for interface counters notifications
	notifChan := make(chan api.Message, 100)
	subs, _ := ch.SubscribeNotification(notifChan, interfaces.NewVnetInterfaceCounters)

	// enable interface counters notifications from VPP
	ch.SendRequest(&vpe.WantStats{
		Pid:           uint32(os.Getpid()),
		EnableDisable: 1,
	}).ReceiveReply(&vpe.WantStatsReply{})

	// create channel for Interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	// loop until Interrupt signal is received
loop:
	for {
		select {
		case <-sigChan:
			// interrupt received
			break loop
		case notifMsg := <-notifChan:
			notif := notifMsg.(*interfaces.VnetInterfaceCounters)
			// notification received
			fmt.Printf("%+v\n", notif)

			if notif.IsCombined == 0 {
				// simple counter
				counters, err := ifcounters.DecodeCounters(ifcounters.VnetInterfaceCounters(*notif))
				if err != nil {
					fmt.Println("Error:", err)
				} else {
					fmt.Printf("%+v\n", counters)
				}
			} else {
				// combined counter
				counters, err := ifcounters.DecodeCombinedCounters(ifcounters.VnetInterfaceCounters(*notif))
				if err != nil {
					fmt.Println("Error:", err)
				} else {
					fmt.Printf("%+v\n", counters)
				}
			}
		}
	}

	// unsubscribe from delivery of the notifications
	ch.UnsubscribeNotification(subs)
}
