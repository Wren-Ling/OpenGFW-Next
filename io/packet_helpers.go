package io

import (
	"hash/crc32"
	"sort"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func packetIPPayload(packet gopacket.Packet) []byte {
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4, ok := ipv4Layer.(*layers.IPv4)
		if !ok {
			return nil
		}
		return layerBytes(ipv4.Contents, ipv4.Payload)
	}
	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6, ok := ipv6Layer.(*layers.IPv6)
		if !ok {
			return nil
		}
		return layerBytes(ipv6.Contents, ipv6.Payload)
	}
	if networkLayer := packet.NetworkLayer(); networkLayer != nil {
		return layerBytes(networkLayer.LayerContents(), networkLayer.LayerPayload())
	}
	return nil
}

func packetStreamID(packet gopacket.Packet) uint32 {
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return 0
	}

	src, dst := networkLayer.NetworkFlow().Endpoints()
	proto := networkLayer.LayerType().String()
	srcEndpoint := src.String()
	dstEndpoint := dst.String()

	if transportLayer := packet.TransportLayer(); transportLayer != nil {
		srcPort, dstPort := transportLayer.TransportFlow().Endpoints()
		proto = transportLayer.LayerType().String()
		srcEndpoint = srcEndpoint + ":" + srcPort.String()
		dstEndpoint = dstEndpoint + ":" + dstPort.String()
	}

	endpoints := []string{srcEndpoint, dstEndpoint}
	sort.Strings(endpoints)
	key := proto + "|" + strings.Join(endpoints, "|")
	return crc32.ChecksumIEEE([]byte(key))
}

func packetMetadata(packet gopacket.Packet) PacketMetadata {
	m := make(PacketMetadata)
	if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
		if ethernet, ok := ethernetLayer.(*layers.Ethernet); ok {
			m["l2.src"] = ethernet.SrcMAC.String()
			m["l2.dst"] = ethernet.DstMAC.String()
			m["l2.type"] = ethernet.EthernetType.String()
		}
	}
	if dot1qLayer := packet.Layer(layers.LayerTypeDot1Q); dot1qLayer != nil {
		if dot1q, ok := dot1qLayer.(*layers.Dot1Q); ok {
			m["vlan.id"] = strconv.Itoa(int(dot1q.VLANIdentifier))
			m["vlan.priority"] = strconv.Itoa(int(dot1q.Priority))
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func layerBytes(contents, payload []byte) []byte {
	if len(contents) == 0 {
		return nil
	}
	out := make([]byte, 0, len(contents)+len(payload))
	out = append(out, contents...)
	out = append(out, payload...)
	return out
}
