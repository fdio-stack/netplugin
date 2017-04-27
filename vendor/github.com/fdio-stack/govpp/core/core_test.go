package core

import (
	"testing"

	"github.com/fdio-stack/govpp/adapter/mock"
	"github.com/fdio-stack/govpp/api"
	"github.com/fdio-stack/govpp/core/bin_api/vpe"
	"github.com/fdio-stack/govpp/examples/bin_api/interfaces"

	. "github.com/onsi/gomega"
)

type testCtx struct {
	mockVpp *mock.VppAdapter
	conn    *Connection
	ch      *api.Channel
}

func setupTest(t *testing.T) *testCtx {
	RegisterTestingT(t)

	ctx := &testCtx{}
	ctx.mockVpp = &mock.VppAdapter{}

	var err error
	ctx.conn, err = Connect(ctx.mockVpp)
	Expect(err).ShouldNot(HaveOccurred())

	ctx.ch, err = ctx.conn.NewAPIChannel()
	Expect(err).ShouldNot(HaveOccurred())

	return ctx
}

func (ctx *testCtx) teardownTest() {
	ctx.ch.Close()
	ctx.conn.Disconnect()
}

func TestSimpleRequest(t *testing.T) {
	ctx := setupTest(t)
	defer ctx.teardownTest()

	ctx.mockVpp.MockReply(&vpe.ControlPingReply{Retval: -5})

	req := &vpe.ControlPing{}
	reply := &vpe.ControlPingReply{}

	// send the request and receive a reply
	ctx.ch.ReqChan <- &api.VppRequest{Message: req}
	vppReply := <-ctx.ch.ReplyChan

	Expect(vppReply).ShouldNot(BeNil())
	Expect(vppReply.Error).ShouldNot(HaveOccurred())

	// decode the message
	err := ctx.ch.MsgDecoder.DecodeMsg(vppReply.Data, reply)
	Expect(err).ShouldNot(HaveOccurred())

	Expect(reply.Retval).To(BeEquivalentTo(-5))
}

func TestMultiRequest(t *testing.T) {
	ctx := setupTest(t)
	defer ctx.teardownTest()

	for m := 0; m < 10; m++ {
		ctx.mockVpp.MockReply(&interfaces.SwInterfaceDetails{})
	}
	ctx.mockVpp.MockReply(&vpe.ControlPingReply{})

	// send multipart request
	ctx.ch.ReqChan <- &api.VppRequest{Message: &interfaces.SwInterfaceDump{}, Multipart: true}

	cnt := 0
	for {
		// receive a reply
		vppReply := <-ctx.ch.ReplyChan
		if vppReply.LastReplyReceived {
			break // break out of the loop
		}
		Expect(vppReply.Error).ShouldNot(HaveOccurred())

		// decode the message
		reply := &interfaces.SwInterfaceDetails{}
		err := ctx.ch.MsgDecoder.DecodeMsg(vppReply.Data, reply)
		Expect(err).ShouldNot(HaveOccurred())
		cnt++
	}

	Expect(cnt).To(BeEquivalentTo(10))
}

func TestNotifications(t *testing.T) {
	ctx := setupTest(t)
	defer ctx.teardownTest()

	// subscribe for notification
	notifChan := make(chan api.Message, 1)
	subscription := &api.NotifSubscription{
		NotifChan:  notifChan,
		MsgFactory: interfaces.NewSwInterfaceSetFlags,
	}
	ctx.ch.NotifSubsChan <- &api.NotifSubscribeRequest{
		Subscription: subscription,
		Subscribe:    true,
	}
	err := <-ctx.ch.NotifSubsReplyChan
	Expect(err).ShouldNot(HaveOccurred())

	// mock the notification and force its delivery
	ctx.mockVpp.MockReply(&interfaces.SwInterfaceSetFlags{
		SwIfIndex:   3,
		AdminUpDown: 1,
	})
	ctx.mockVpp.SendMsg(0, []byte{0})

	// receive the notification
	notif := (<-notifChan).(*interfaces.SwInterfaceSetFlags)

	Expect(notif.SwIfIndex).To(BeEquivalentTo(3))

	// unsubscribe notification
	ctx.ch.NotifSubsChan <- &api.NotifSubscribeRequest{
		Subscription: subscription,
		Subscribe:    false,
	}
	err = <-ctx.ch.NotifSubsReplyChan
	Expect(err).ShouldNot(HaveOccurred())
}

func TestDoubleConnection(t *testing.T) {
	ctx := setupTest(t)
	defer ctx.teardownTest()

	conn, err := Connect(ctx.mockVpp)
	Expect(err).Should(HaveOccurred())
	Expect(err.Error()).To(ContainSubstring("only one connection per process"))
	Expect(conn).Should(BeNil())
}

func TestFullBuffer(t *testing.T) {
	ctx := setupTest(t)
	defer ctx.teardownTest()

	// close the default API channel
	ctx.ch.Close()

	// create a new channel with limited buffer sizes
	var err error
	ctx.ch, err = ctx.conn.NewAPIChannelBuffered(10, 1)
	Expect(err).ShouldNot(HaveOccurred())

	// send multiple requests, only one reply should be read
	for i := 0; i < 20; i++ {
		ctx.mockVpp.MockReply(&vpe.ControlPingReply{})
		ctx.ch.ReqChan <- &api.VppRequest{Message: &vpe.ControlPing{}}
	}

	vppReply := <-ctx.ch.ReplyChan
	Expect(vppReply).ShouldNot(BeNil())

	received := false
	select {
	case vppReply = <-ctx.ch.ReplyChan:
		received = true // this should not happen
	default:
		received = false // no reply to be received
	}
	Expect(received).Should(BeFalse(), "A reply has been recieved, should had been ignored.")
}

func TestCodec(t *testing.T) {
	RegisterTestingT(t)

	codec := &MsgCodec{}

	// request
	data, err := codec.EncodeMsg(&vpe.CreateLoopback{MacAddress: []byte{1, 2, 3, 4, 5, 6}}, 11)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(data).ShouldNot(BeEmpty())

	msg1 := &vpe.CreateLoopback{}
	err = codec.DecodeMsg(data, msg1)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(msg1.MacAddress).To(BeEquivalentTo([]byte{1, 2, 3, 4, 5, 6}))

	// reply
	data, err = codec.EncodeMsg(&vpe.ControlPingReply{Retval: 55}, 22)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(data).ShouldNot(BeEmpty())

	msg2 := &vpe.ControlPingReply{}
	err = codec.DecodeMsg(data, msg2)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(msg2.Retval).To(BeEquivalentTo(55))

	// other
	data, err = codec.EncodeMsg(&vpe.VnetIP4FibCounters{VrfID: 77}, 33)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(data).ShouldNot(BeEmpty())

	msg3 := &vpe.VnetIP4FibCounters{}
	err = codec.DecodeMsg(data, msg3)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(msg3.VrfID).To(BeEquivalentTo(77))
}

func TestCodecNegative(t *testing.T) {
	RegisterTestingT(t)

	codec := &MsgCodec{}

	// nil message for encoding
	data, err := codec.EncodeMsg(nil, 15)
	Expect(err).Should(HaveOccurred())
	Expect(err.Error()).To(ContainSubstring("nil message"))
	Expect(data).Should(BeNil())

	// nil message for decoding
	err = codec.DecodeMsg(data, nil)
	Expect(err).Should(HaveOccurred())
	Expect(err.Error()).To(ContainSubstring("nil message"))

	// nil data for decoding
	err = codec.DecodeMsg(nil, &vpe.ControlPingReply{})
	Expect(err).Should(HaveOccurred())
	Expect(err.Error()).To(ContainSubstring("EOF"))
}
