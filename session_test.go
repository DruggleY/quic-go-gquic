package quic

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/testdata"
	"github.com/lucas-clemente/quic-go/utils"
)

type mockConnection struct {
	written [][]byte
}

func (m *mockConnection) write(p []byte) error {
	m.written = append(m.written, p)
	return nil
}

func (*mockConnection) setCurrentRemoteAddr(addr interface{}) {}

// TODO: Reorganize
var _ = Describe("Session", func() {
	var (
		session        *Session
		callbackCalled bool
		conn           *mockConnection
	)

	BeforeEach(func() {
		conn = &mockConnection{}
		callbackCalled = false
		session = &Session{
			conn:                        conn,
			streams:                     make(map[protocol.StreamID]*stream),
			streamCallback:              func(*Session, utils.Stream) { callbackCalled = true },
			connectionParametersManager: handshake.NewConnectionParamatersManager(),
		}
	})

	Context("when handling stream frames", func() {
		It("makes new streams", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
			})
			Expect(session.streams).To(HaveLen(1))
			Expect(callbackCalled).To(BeTrue())
			p := make([]byte, 4)
			_, err := session.streams[5].Read(p)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
		})

		It("handles existing streams", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca},
			})
			Expect(session.streams).To(HaveLen(1))
			Expect(callbackCalled).To(BeTrue())
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Offset:   2,
				Data:     []byte{0xfb, 0xad},
			})
			Expect(session.streams).To(HaveLen(1))
			p := make([]byte, 4)
			_, err := session.streams[5].Read(p)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
		})

		It("closes streams with FIN bits", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
				FinBit:   true,
			})
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).ToNot(BeNil())
			Expect(callbackCalled).To(BeTrue())
			p := make([]byte, 4)
			_, err := session.streams[5].Read(p)
			Expect(err).To(Equal(io.EOF))
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
			session.garbageCollectStreams()
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).To(BeNil())
		})

		It("closes streams with error", func() {
			testErr := errors.New("test")
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
			})
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).ToNot(BeNil())
			Expect(callbackCalled).To(BeTrue())
			p := make([]byte, 4)
			_, err := session.streams[5].Read(p)
			Expect(err).ToNot(HaveOccurred())
			session.closeStreamsWithError(testErr)
			_, err = session.streams[5].Read(p)
			Expect(err).To(Equal(testErr))
			session.garbageCollectStreams()
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).To(BeNil())
		})

		It("closes empty streams with error", func() {
			testErr := errors.New("test")
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
			})
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).ToNot(BeNil())
			Expect(callbackCalled).To(BeTrue())
			session.closeStreamsWithError(testErr)
			_, err := session.streams[5].Read([]byte{0})
			Expect(err).To(Equal(testErr))
			session.garbageCollectStreams()
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).To(BeNil())
		})

		It("rejects streams that existed previously", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{},
				FinBit:   true,
			})
			_, err := session.streams[5].Read([]byte{0})
			Expect(err).To(Equal(io.EOF))
			session.garbageCollectStreams()
			err = session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{},
			})
			Expect(err).To(MatchError("Session: reopening streams is not allowed"))
		})
	})

	Context("handling RST_STREAM frames", func() {
		It("closes the receiving streams for writing and reading", func() {
			s, err := session.NewStream(5)
			Expect(err).ToNot(HaveOccurred())
			err = session.handleRstStreamFrame(&frames.RstStreamFrame{
				StreamID:  5,
				ErrorCode: 42,
			})
			Expect(err).ToNot(HaveOccurred())
			n, err := s.Write([]byte{0})
			Expect(n).To(BeZero())
			Expect(err).To(MatchError("RST_STREAM received with code 42"))
			n, err = s.Read([]byte{0})
			Expect(n).To(BeZero())
			Expect(err).To(MatchError("RST_STREAM received with code 42"))
		})

		It("errors when the stream is not known", func() {
			err := session.handleRstStreamFrame(&frames.RstStreamFrame{
				StreamID:  5,
				ErrorCode: 42,
			})
			Expect(err).To(MatchError(errRstStreamOnInvalidStream))
		})
	})

	Context("handling WINDOW_UPDATE frames", func() {
		It("updates the Flow Control Windows of a stream", func() {
			_, err := session.NewStream(5)
			Expect(err).ToNot(HaveOccurred())
			err = session.handleWindowUpdateFrame(&frames.WindowUpdateFrame{
				StreamID:   5,
				ByteOffset: 0x8000,
			})
			Expect(err).ToNot(HaveOccurred())
		})

		It("errors when the stream is not known", func() {
			err := session.handleWindowUpdateFrame(&frames.WindowUpdateFrame{
				StreamID:   5,
				ByteOffset: 1337,
			})
			Expect(err).To(MatchError(errWindowUpdateOnInvalidStream))
		})
	})

	Context("closing", func() {
		var (
			nGoRoutinesBefore int
			closed            bool
		)

		BeforeEach(func() {
			time.Sleep(1 * time.Millisecond) // Wait for old goroutines to finish
			nGoRoutinesBefore = runtime.NumGoroutine()
			signer, err := crypto.NewRSASigner(testdata.GetTLSConfig())
			Expect(err).ToNot(HaveOccurred())
			scfg := handshake.NewServerConfig(crypto.NewCurve25519KEX(), signer)
			session = NewSession(conn, 0, 0, scfg, nil, func(*Session) { closed = true }).(*Session)
			go session.Run()
			Expect(runtime.NumGoroutine()).To(Equal(nGoRoutinesBefore + 2))
		})

		It("shuts down without error", func() {
			session.Close(nil, true)
			Expect(closed).To(BeTrue())
			time.Sleep(1 * time.Millisecond)
			Expect(runtime.NumGoroutine()).To(Equal(nGoRoutinesBefore))
		})

		It("closes streams with proper error", func() {
			testErr := errors.New("test error")
			s, err := session.NewStream(5)
			Expect(err).NotTo(HaveOccurred())
			session.Close(testErr, true)
			Expect(closed).To(BeTrue())
			time.Sleep(1 * time.Millisecond)
			Expect(runtime.NumGoroutine()).To(Equal(nGoRoutinesBefore))
			n, err := s.Read([]byte{0})
			Expect(n).To(BeZero())
			Expect(err).To(Equal(testErr))
			n, err = s.Write([]byte{0})
			Expect(n).To(BeZero())
			Expect(err).To(Equal(testErr))
		})
	})

	Context("sending packets", func() {
		BeforeEach(func() {
			signer, err := crypto.NewRSASigner(testdata.GetTLSConfig())
			Expect(err).ToNot(HaveOccurred())
			scfg := handshake.NewServerConfig(crypto.NewCurve25519KEX(), signer)
			session = NewSession(conn, 0, 0, scfg, nil, nil).(*Session)
		})

		It("sends ack frames", func() {
			session.receivedPacketHandler.ReceivedPacket(1, true)
			err := session.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(conn.written).To(HaveLen(1))
			Expect(conn.written[0]).To(ContainSubstring(string([]byte{0x4c, 0x2, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0})))
		})

		It("sends queued stream frames", func() {
			session.QueueStreamFrame(&frames.StreamFrame{
				StreamID: 1,
				Data:     []byte("foobar"),
			})
			session.receivedPacketHandler.ReceivedPacket(1, true)
			err := session.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(conn.written).To(HaveLen(1))
			Expect(conn.written[0]).To(ContainSubstring(string([]byte{0x4c, 0x2, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0})))
			Expect(conn.written[0]).To(ContainSubstring(string("foobar")))
		})

		It("sends public reset", func() {
			err := session.sendPublicReset(1)
			Expect(err).NotTo(HaveOccurred())
			Expect(conn.written).To(HaveLen(1))
			Expect(conn.written[0]).To(ContainSubstring(string([]byte("PRST"))))
		})
	})

	Context("scheduling sending", func() {
		BeforeEach(func() {
			signer, err := crypto.NewRSASigner(testdata.GetTLSConfig())
			Expect(err).ToNot(HaveOccurred())
			scfg := handshake.NewServerConfig(crypto.NewCurve25519KEX(), signer)
			session = NewSession(conn, 0, 0, scfg, nil, func(*Session) {}).(*Session)
		})

		It("sends after queuing a stream frame", func() {
			Expect(session.sendingScheduled).NotTo(Receive())
			err := session.QueueStreamFrame(&frames.StreamFrame{StreamID: 1})
			Expect(err).ToNot(HaveOccurred())
			// Try again, so that we detect blocking scheduleSending
			err = session.QueueStreamFrame(&frames.StreamFrame{StreamID: 1})
			Expect(err).ToNot(HaveOccurred())
			Expect(session.sendingScheduled).To(Receive())
		})

		It("sends after receiving a packet", func() {
			Expect(session.sendingScheduled).NotTo(Receive())
			session.receivedPackets <- receivedPacket{
				publicHeader: &PublicHeader{},
				r: bytes.NewReader([]byte{
					// FNV hash + "foobar"
					0x18, 0x6f, 0x44, 0xba, 0x97, 0x35, 0xd, 0x6f, 0xbf, 0x64, 0x3c, 0x79, 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72,
				}),
			}
			session.Run()
			Expect(session.sendingScheduled).To(Receive())
		})
	})

	It("closes when crypto stream errors", func() {
		signer, err := crypto.NewRSASigner(testdata.GetTLSConfig())
		Expect(err).ToNot(HaveOccurred())
		scfg := handshake.NewServerConfig(crypto.NewCurve25519KEX(), signer)
		session = NewSession(conn, 0, 0, scfg, nil, func(*Session) {}).(*Session)
		s, err := session.NewStream(3)
		Expect(err).NotTo(HaveOccurred())
		err = session.handleStreamFrame(&frames.StreamFrame{
			StreamID: 1,
			Data:     []byte("4242\x00\x00\x00\x00"),
		})
		Expect(err).NotTo(HaveOccurred())
		time.Sleep(time.Millisecond)
		Expect(session.closed).To(BeTrue())
		_, err = s.Write([]byte{})
		Expect(err).To(MatchError("CryptoSetup: expected CHLO"))
	})

	// See https://github.com/lucas-clemente/quic-go/issues/38
	PIt("sends public reset when receiving invalid message", func() {
		signer, err := crypto.NewRSASigner(testdata.GetTLSConfig())
		Expect(err).ToNot(HaveOccurred())
		scfg := handshake.NewServerConfig(crypto.NewCurve25519KEX(), signer)
		session = NewSession(conn, 0, 0, scfg, nil, nil).(*Session)
		hdr := &PublicHeader{
			PacketNumber: 42,
		}
		r := bytes.NewReader([]byte("foo"))
		err = session.handlePacket(nil, hdr, r)
		Expect(err).To(HaveOccurred())
		// Close() should send public reset
		err = session.Close(err, true)
		Expect(err).NotTo(HaveOccurred())
		Expect(conn.written).To(HaveLen(1))
		Expect(conn.written[0]).To(ContainSubstring(string([]byte("PRST"))))
	})
})