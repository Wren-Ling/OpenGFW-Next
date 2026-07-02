package internal

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/utils"
)

// TLS record types.
const (
	RecordTypeHandshake = 0x16
)

// TLS handshake message types.
const (
	TypeClientHello = 0x01
	TypeServerHello = 0x02
)

// TLS extension numbers.
const (
	extServerName           = 0x0000
	extSupportedGroups      = 0x000a
	extECPointFormats       = 0x000b
	extSignatureAlgorithms  = 0x000d
	extALPN                 = 0x0010
	extSupportedVersions    = 0x002b
	extEncryptedClientHello = 0xfe0d
)

func ParseTLSClientHelloMsgData(chBuf *utils.ByteBuffer) analyzer.PropMap {
	return parseTLSClientHelloMsgData(chBuf, "t")
}

func ParseQUICClientHelloMsgData(chBuf *utils.ByteBuffer) analyzer.PropMap {
	return parseTLSClientHelloMsgData(chBuf, "q")
}

func parseTLSClientHelloMsgData(chBuf *utils.ByteBuffer, ja4Protocol string) analyzer.PropMap {
	var ok bool
	m := make(analyzer.PropMap)
	// Version, random & session ID length combined are within 35 bytes,
	// so no need for bounds checking
	m["version"], _ = chBuf.GetUint16(false, true)
	m["random"], _ = chBuf.Get(32, true)
	sessionIDLen, _ := chBuf.GetByte(true)
	m["session"], ok = chBuf.Get(int(sessionIDLen), true)
	if !ok {
		// Not enough data for session ID
		return nil
	}
	cipherSuitesLen, ok := chBuf.GetUint16(false, true)
	if !ok {
		// Not enough data for cipher suites length
		return nil
	}
	if cipherSuitesLen%2 != 0 {
		// Cipher suites are 2 bytes each, so must be even
		return nil
	}
	ciphers := make([]uint16, cipherSuitesLen/2)
	for i := range ciphers {
		ciphers[i], ok = chBuf.GetUint16(false, true)
		if !ok {
			return nil
		}
	}
	m["ciphers"] = ciphers
	m["cipher_count"] = len(ciphers)
	compressionMethodsLen, ok := chBuf.GetByte(true)
	if !ok {
		// Not enough data for compression methods length
		return nil
	}
	// Compression methods are 1 byte each, we just put a byte slice here
	m["compression"], ok = chBuf.Get(int(compressionMethodsLen), true)
	if !ok {
		// Not enough data for compression methods
		return nil
	}
	extsLen, ok := chBuf.GetUint16(false, true)
	if !ok {
		// No extensions, I guess it's possible?
		m["extension_types"] = []uint16(nil)
		addTLSClientHelloFingerprint(m, nil, ja4Protocol)
		return m
	}
	extBuf, ok := chBuf.GetSubBuffer(int(extsLen), true)
	if !ok {
		// Not enough data for extensions
		return nil
	}
	extensionTypes := make([]uint16, 0)
	for extBuf.Len() > 0 {
		extType, ok := extBuf.GetUint16(false, true)
		if !ok {
			// Not enough data for extension type
			return nil
		}
		extLen, ok := extBuf.GetUint16(false, true)
		if !ok {
			// Not enough data for extension length
			return nil
		}
		extensionTypes = append(extensionTypes, extType)
		extDataBuf, ok := extBuf.GetSubBuffer(int(extLen), true)
		if !ok || !parseTLSExtensions(extType, extDataBuf, m) {
			// Not enough data for extension data, or invalid extension
			return nil
		}
	}
	m["extension_types"] = extensionTypes
	addTLSClientHelloFingerprint(m, extensionTypes, ja4Protocol)
	return m
}

func ParseTLSServerHelloMsgData(shBuf *utils.ByteBuffer) analyzer.PropMap {
	var ok bool
	m := make(analyzer.PropMap)
	// Version, random & session ID length combined are within 35 bytes,
	// so no need for bounds checking
	m["version"], _ = shBuf.GetUint16(false, true)
	m["random"], _ = shBuf.Get(32, true)
	sessionIDLen, _ := shBuf.GetByte(true)
	m["session"], ok = shBuf.Get(int(sessionIDLen), true)
	if !ok {
		// Not enough data for session ID
		return nil
	}
	cipherSuite, ok := shBuf.GetUint16(false, true)
	if !ok {
		// Not enough data for cipher suite
		return nil
	}
	m["cipher"] = cipherSuite
	compressionMethod, ok := shBuf.GetByte(true)
	if !ok {
		// Not enough data for compression method
		return nil
	}
	m["compression"] = compressionMethod
	extsLen, ok := shBuf.GetUint16(false, true)
	if !ok {
		// No extensions, I guess it's possible?
		return m
	}
	extBuf, ok := shBuf.GetSubBuffer(int(extsLen), true)
	if !ok {
		// Not enough data for extensions
		return nil
	}
	for extBuf.Len() > 0 {
		extType, ok := extBuf.GetUint16(false, true)
		if !ok {
			// Not enough data for extension type
			return nil
		}
		extLen, ok := extBuf.GetUint16(false, true)
		if !ok {
			// Not enough data for extension length
			return nil
		}
		extDataBuf, ok := extBuf.GetSubBuffer(int(extLen), true)
		if !ok || !parseTLSExtensions(extType, extDataBuf, m) {
			// Not enough data for extension data, or invalid extension
			return nil
		}
	}
	return m
}

func parseTLSExtensions(extType uint16, extDataBuf *utils.ByteBuffer, m analyzer.PropMap) bool {
	switch extType {
	case extServerName:
		ok := extDataBuf.Skip(2) // Ignore list length, we only care about the first entry for now
		if !ok {
			// Not enough data for list length
			return false
		}
		sniType, ok := extDataBuf.GetByte(true)
		if !ok || sniType != 0 {
			// Not enough data for SNI type, or not hostname
			return false
		}
		sniLen, ok := extDataBuf.GetUint16(false, true)
		if !ok {
			// Not enough data for SNI length
			return false
		}
		m["sni"], ok = extDataBuf.GetString(int(sniLen), true)
		if !ok {
			// Not enough data for SNI
			return false
		}
	case extALPN:
		ok := extDataBuf.Skip(2) // Ignore list length, as we read until the end
		if !ok {
			// Not enough data for list length
			return false
		}
		var alpnList []string
		for extDataBuf.Len() > 0 {
			alpnLen, ok := extDataBuf.GetByte(true)
			if !ok {
				// Not enough data for ALPN length
				return false
			}
			alpn, ok := extDataBuf.GetString(int(alpnLen), true)
			if !ok {
				// Not enough data for ALPN
				return false
			}
			alpnList = append(alpnList, alpn)
		}
		m["alpn"] = alpnList
	case extSupportedGroups:
		ok := extDataBuf.Skip(2) // Ignore list length, as we read until the end
		if !ok {
			// Not enough data for list length
			return false
		}
		var groups []uint16
		for extDataBuf.Len() > 0 {
			group, ok := extDataBuf.GetUint16(false, true)
			if !ok {
				// Not enough data for group
				return false
			}
			groups = append(groups, group)
		}
		m["supported_groups"] = groups
	case extECPointFormats:
		ok := extDataBuf.Skip(1) // Ignore list length, as we read until the end
		if !ok {
			// Not enough data for list length
			return false
		}
		var formats []uint8
		for extDataBuf.Len() > 0 {
			format, ok := extDataBuf.GetByte(true)
			if !ok {
				// Not enough data for point format
				return false
			}
			formats = append(formats, format)
		}
		m["ec_point_formats"] = formats
	case extSignatureAlgorithms:
		ok := extDataBuf.Skip(2) // Ignore list length, as we read until the end
		if !ok {
			// Not enough data for list length
			return false
		}
		var algorithms []uint16
		for extDataBuf.Len() > 0 {
			algorithm, ok := extDataBuf.GetUint16(false, true)
			if !ok {
				// Not enough data for signature algorithm
				return false
			}
			algorithms = append(algorithms, algorithm)
		}
		m["signature_algorithms"] = algorithms
	case extSupportedVersions:
		if extDataBuf.Len() == 2 {
			// Server only selects one version
			m["supported_versions"], _ = extDataBuf.GetUint16(false, true)
		} else {
			// Client sends a list of versions
			ok := extDataBuf.Skip(1) // Ignore list length, as we read until the end
			if !ok {
				// Not enough data for list length
				return false
			}
			var versions []uint16
			for extDataBuf.Len() > 0 {
				ver, ok := extDataBuf.GetUint16(false, true)
				if !ok {
					// Not enough data for version
					return false
				}
				versions = append(versions, ver)
			}
			m["supported_versions"] = versions
		}
	case extEncryptedClientHello:
		// We can't parse ECH for now, just set a flag
		m["ech"] = true
	}
	return true
}

func addTLSClientHelloFingerprint(m analyzer.PropMap, extensionTypes []uint16, ja4Protocol string) {
	if _, ok := m["ech"]; !ok {
		m["ech"] = false
	}

	version, _ := m["version"].(uint16)
	ciphers, _ := m["ciphers"].([]uint16)
	groups, _ := m["supported_groups"].([]uint16)
	pointFormats, _ := m["ec_point_formats"].([]uint8)
	signatureAlgorithms, _ := m["signature_algorithms"].([]uint16)

	ja3 := strings.Join([]string{
		strconv.Itoa(int(version)),
		joinUint16sJA3(ciphers),
		joinUint16sJA3(extensionTypes),
		joinUint16sJA3(groups),
		joinUint8s(pointFormats),
	}, ",")
	hash := md5.Sum([]byte(ja3))
	m["ja3"] = ja3
	m["ja3_hash"] = hex.EncodeToString(hash[:])
	m["ja4"] = buildJA4(ja4Protocol, version, m["supported_versions"], m["sni"], ciphers, extensionTypes, m["alpn"], signatureAlgorithms)
	delete(m, "supported_groups")
	delete(m, "ec_point_formats")
	delete(m, "signature_algorithms")
}

func joinUint16sJA3(values []uint16) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		if isGREASE(value) {
			continue
		}
		parts = append(parts, strconv.Itoa(int(value)))
	}
	return strings.Join(parts, "-")
}

func joinUint8s(values []uint8) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(int(value)))
	}
	return strings.Join(parts, "-")
}

func isGREASE(value uint16) bool {
	high := byte(value >> 8)
	low := byte(value)
	return high == low && high&0x0f == 0x0a
}

func buildJA4(protocol string, version uint16, supportedVersions interface{}, sni interface{}, ciphers []uint16, extensionTypes []uint16, alpn interface{}, signatureAlgorithms []uint16) string {
	if protocol == "" {
		protocol = "t"
	}
	cipherValues := filterGREASE(ciphers)
	extensionValues := filterGREASE(extensionTypes)
	versionCode := ja4TLSVersion(version, supportedVersions)
	sniFlag := "i"
	if _, ok := sni.(string); ok {
		sniFlag = "d"
	}
	alpnCode := ja4ALPN(alpn)
	cipherHash := ja4HashHexValues(cipherValues)
	extensionHash := ja4ExtensionHash(extensionValues, signatureAlgorithms)
	return fmt.Sprintf("%s%s%s%02d%02d%s_%s_%s",
		protocol,
		versionCode,
		sniFlag,
		min(len(cipherValues), 99),
		min(len(extensionValues), 99),
		alpnCode,
		cipherHash,
		extensionHash,
	)
}

func ja4TLSVersion(version uint16, supportedVersions interface{}) string {
	if versions, ok := supportedVersions.([]uint16); ok && len(versions) > 0 {
		values := filterGREASE(versions)
		if len(values) > 0 {
			sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
			version = values[len(values)-1]
		}
	}
	switch version {
	case 0x0002:
		return "s2"
	case 0x0300:
		return "s3"
	case 0x0301:
		return "10"
	case 0x0302:
		return "11"
	case 0x0303:
		return "12"
	case 0x0304:
		return "13"
	default:
		return "00"
	}
}

func ja4ALPN(alpn interface{}) string {
	var value string
	if values, ok := alpn.([]string); ok && len(values) > 0 {
		value = values[0]
	} else if s, ok := alpn.(string); ok {
		value = s
	}
	if value == "" {
		return "00"
	}
	if value[0] > 127 {
		return "99"
	}
	if len(value) > 2 {
		return string([]byte{value[0], value[len(value)-1]})
	}
	return value
}

func ja4ExtensionHash(extensionValues, signatureAlgorithms []uint16) string {
	values := make([]uint16, 0, len(extensionValues))
	for _, value := range extensionValues {
		if value == extServerName || value == extALPN {
			continue
		}
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	parts := ja4HexParts(values)
	if len(signatureAlgorithms) > 0 {
		sigParts := ja4HexParts(filterGREASE(signatureAlgorithms))
		if len(sigParts) > 0 {
			return ja4SHA12(strings.Join(parts, ",") + "_" + strings.Join(sigParts, ","))
		}
	}
	if len(parts) == 0 {
		return "000000000000"
	}
	return ja4SHA12(strings.Join(parts, ","))
}

func ja4HashHexValues(values []uint16) string {
	if len(values) == 0 {
		return "000000000000"
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return ja4SHA12(strings.Join(ja4HexParts(values), ","))
}

func ja4HexParts(values []uint16) []string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, fmt.Sprintf("%04x", value))
	}
	return parts
}

func filterGREASE(values []uint16) []uint16 {
	out := make([]uint16, 0, len(values))
	for _, value := range values {
		if !isGREASE(value) {
			out = append(out, value)
		}
	}
	return out
}

func ja4SHA12(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])[:12]
}
