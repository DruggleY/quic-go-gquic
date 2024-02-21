package quic

import (
	"bytes"
	"fmt"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"io"
)

// ParseSNIFromClientHelloGQUICPacket ：解析gquic 尤其针对Q043
// 主要参考： https://github.com/quic-go/quic-go gquic分支
func ParseSNIFromClientHelloGQUICPacket(packet []byte) (string, error) {
	// packet_handler_map.go:141 handlePacket
	if len(packet) < 20 {
		return "", fmt.Errorf("packet too short")
	}
	if packet[0]&0x80 > 0 || packet[0]&0x38 == 0x30 {
		return "", fmt.Errorf("is not gquic")
	}
	r := bytes.NewReader(packet)
	iHdr, err := wire.ParseInvariantHeader(r, 8)
	// drop the packet if we can't parse the header
	if err != nil {
		return "", fmt.Errorf("error parsing invariant header: %s", err)
	}

	hdr, err := iHdr.Parse(r, protocol.PerspectiveClient, 0)
	if err != nil {
		return "", fmt.Errorf("error parsing header: %s", err)
	}

	// internal/crypto/null_aead_fnv128a.go
	if hdr.Version.UsesIETFFrameFormat() || r.Len() < 16 {
		return "", fmt.Errorf("no frame")
	}

	_, _ = r.Seek(12, io.SeekCurrent)
	for {
		frame, err := wire.ParseNextFrame(r, hdr, hdr.Version)
		if err != nil {
			return "", err
		}
		if frame == nil {
			return "", nil
		}
		if sf, is := frame.(*wire.StreamFrame); is {
			// internal/handshake/handshake_message
			message, err := handshake.ParseHandshakeMessage(bytes.NewReader(sf.Data))
			if err == nil && message.Tag == handshake.TagCHLO {
				for tag, value := range message.Data {
					if tag == handshake.TagSNI && len(value) > 0 {
						return string(value), nil
					}
				}
			}
		}
	}
}
