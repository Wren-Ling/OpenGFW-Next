package udp

import (
	"time"

	"github.com/apernet/OpenGFW/analyzer"
)

const (
	udpFlowLongLivedThreshold = 30 * time.Second
)

var (
	_ analyzer.UDPAnalyzer = (*UDPFlowAnalyzer)(nil)
	_ analyzer.UDPStream   = (*udpFlowStream)(nil)
)

type UDPFlowAnalyzer struct{}

func (a *UDPFlowAnalyzer) Name() string {
	return "udpflow"
}

func (a *UDPFlowAnalyzer) Limit() int {
	return 0
}

func (a *UDPFlowAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	return &udpFlowStream{
		srcPort: info.SrcPort,
		dstPort: info.DstPort,
		now:     time.Now,
	}
}

type udpFlowStream struct {
	srcPort uint16
	dstPort uint16
	now     func() time.Time

	started        time.Time
	lastSeen       time.Time
	packetCount    int
	txPacketCount  int
	rxPacketCount  int
	firstPacketLen int
	minPacketLen   int
	maxPacketLen   int
	totalBytes     int
	txBytes        int
	rxBytes        int
	lenBuckets     [8]int
	firstLens      [4]int
	firstTXLen     int
	firstRXLen     int
	lastDirection  int
	currentRun     int
	maxRun         int
	directionTurns int
}

func (s *udpFlowStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
	now := s.currentTime()
	if s.packetCount == 0 {
		s.started = now
		s.firstPacketLen = len(data)
	}
	s.lastSeen = now
	s.packetCount++
	if rev {
		s.rxPacketCount++
	} else {
		s.txPacketCount++
	}

	packetLen := len(data)
	if s.packetCount <= len(s.firstLens) {
		s.firstLens[s.packetCount-1] = packetLen
	}
	if rev && s.firstRXLen == 0 {
		s.firstRXLen = packetLen
	}
	if !rev && s.firstTXLen == 0 {
		s.firstTXLen = packetLen
	}
	s.updateDirectionRun(rev)
	s.totalBytes += packetLen
	if rev {
		s.rxBytes += packetLen
	} else {
		s.txBytes += packetLen
	}
	if s.minPacketLen == 0 || packetLen < s.minPacketLen {
		s.minPacketLen = packetLen
	}
	if packetLen > s.maxPacketLen {
		s.maxPacketLen = packetLen
	}
	s.lenBuckets[udpFlowLenBucket(packetLen)]++

	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateMerge,
		M:    s.propMap(now),
	}, false
}

func (s *udpFlowStream) Close(limited bool) *analyzer.PropUpdate {
	return nil
}

func (s *udpFlowStream) propMap(now time.Time) analyzer.PropMap {
	avgLen := 0.0
	if s.packetCount > 0 {
		avgLen = float64(s.totalBytes) / float64(s.packetCount)
	}
	durationSeconds := s.duration(now).Seconds()
	packetRate := 0.0
	byteRate := 0.0
	if durationSeconds > 0 {
		packetRate = float64(s.packetCount) / durationSeconds
		byteRate = float64(s.totalBytes) / durationSeconds
	}
	largePacketRatio := 0.0
	smallPacketRatio := 0.0
	txPacketRatio := 0.0
	rxPacketRatio := 0.0
	txByteRatio := 0.0
	rxByteRatio := 0.0
	largePackets := 0
	smallPackets := 0
	if s.packetCount > 0 {
		largePackets = s.lenBuckets[6] + s.lenBuckets[7]
		smallPackets = s.lenBuckets[1] + s.lenBuckets[2]
		largePacketRatio = float64(largePackets) / float64(s.packetCount)
		smallPacketRatio = float64(smallPackets) / float64(s.packetCount)
		txPacketRatio = float64(s.txPacketCount) / float64(s.packetCount)
		rxPacketRatio = float64(s.rxPacketCount) / float64(s.packetCount)
	}
	if s.totalBytes > 0 {
		txByteRatio = float64(s.txBytes) / float64(s.totalBytes)
		rxByteRatio = float64(s.rxBytes) / float64(s.totalBytes)
	}
	return analyzer.PropMap{
		"src_port":                s.srcPort,
		"dst_port":                s.dstPort,
		"packet_count":            s.packetCount,
		"tx_packet_count":         s.txPacketCount,
		"rx_packet_count":         s.rxPacketCount,
		"tx_packet_ratio":         txPacketRatio,
		"rx_packet_ratio":         rxPacketRatio,
		"first_packet_len":        s.firstPacketLen,
		"second_packet_len":       s.firstLens[1],
		"third_packet_len":        s.firstLens[2],
		"fourth_packet_len":       s.firstLens[3],
		"first_tx_packet_len":     s.firstTXLen,
		"first_rx_packet_len":     s.firstRXLen,
		"min_packet_len":          s.minPacketLen,
		"max_packet_len":          s.maxPacketLen,
		"avg_packet_len":          avgLen,
		"tx_bytes":                s.txBytes,
		"rx_bytes":                s.rxBytes,
		"total_bytes":             s.totalBytes,
		"tx_byte_ratio":           txByteRatio,
		"rx_byte_ratio":           rxByteRatio,
		"duration_seconds":        durationSeconds,
		"packet_rate":             packetRate,
		"byte_rate":               byteRate,
		"long_lived":              s.duration(now) >= udpFlowLongLivedThreshold,
		"bidirectional":           s.txPacketCount > 0 && s.rxPacketCount > 0,
		"large_packet_count":      largePackets,
		"large_packet_ratio":      largePacketRatio,
		"small_packet_count":      smallPackets,
		"small_packet_ratio":      smallPacketRatio,
		"direction_change_count":  s.directionTurns,
		"max_same_direction_run":  s.maxRun,
		"tx_dominant":             txPacketRatio >= 0.80,
		"rx_dominant":             rxPacketRatio >= 0.80,
		"balanced_directions":     txPacketRatio >= 0.20 && rxPacketRatio >= 0.20,
		"len_bucket_empty_count":  s.lenBuckets[0],
		"len_bucket_le64_count":   s.lenBuckets[1],
		"len_bucket_le128_count":  s.lenBuckets[2],
		"len_bucket_le256_count":  s.lenBuckets[3],
		"len_bucket_le512_count":  s.lenBuckets[4],
		"len_bucket_le1024_count": s.lenBuckets[5],
		"len_bucket_le1200_count": s.lenBuckets[6],
		"len_bucket_gt1200_count": s.lenBuckets[7],
		"len_bucket_empty_ratio":  udpFlowRatio(s.lenBuckets[0], s.packetCount),
		"len_bucket_le64_ratio":   udpFlowRatio(s.lenBuckets[1], s.packetCount),
		"len_bucket_le128_ratio":  udpFlowRatio(s.lenBuckets[2], s.packetCount),
		"len_bucket_le256_ratio":  udpFlowRatio(s.lenBuckets[3], s.packetCount),
		"len_bucket_le512_ratio":  udpFlowRatio(s.lenBuckets[4], s.packetCount),
		"len_bucket_le1024_ratio": udpFlowRatio(s.lenBuckets[5], s.packetCount),
		"len_bucket_le1200_ratio": udpFlowRatio(s.lenBuckets[6], s.packetCount),
		"len_bucket_gt1200_ratio": udpFlowRatio(s.lenBuckets[7], s.packetCount),
		"udp443":                  s.dstPort == 443,
	}
}

func (s *udpFlowStream) updateDirectionRun(rev bool) {
	direction := 1
	if rev {
		direction = 2
	}
	if s.lastDirection == 0 {
		s.currentRun = 1
		s.maxRun = 1
		s.lastDirection = direction
		return
	}
	if s.lastDirection == direction {
		s.currentRun++
	} else {
		s.directionTurns++
		s.currentRun = 1
		s.lastDirection = direction
	}
	if s.currentRun > s.maxRun {
		s.maxRun = s.currentRun
	}
}

func (s *udpFlowStream) duration(now time.Time) time.Duration {
	if s.started.IsZero() {
		return 0
	}
	return now.Sub(s.started)
}

func (s *udpFlowStream) currentTime() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func udpFlowLenBucket(packetLen int) int {
	switch {
	case packetLen <= 0:
		return 0
	case packetLen <= 64:
		return 1
	case packetLen <= 128:
		return 2
	case packetLen <= 256:
		return 3
	case packetLen <= 512:
		return 4
	case packetLen <= 1024:
		return 5
	case packetLen <= 1200:
		return 6
	default:
		return 7
	}
}

func udpFlowRatio(count, total int) float64 {
	if total <= 0 {
		return 0
	}
	return float64(count) / float64(total)
}
