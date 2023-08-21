package runner

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"
)

func GenerateRequestPDU(signature string) []byte {
	// 预限制 signature 长度 120
	if len(signature) > 120 {
		signature = signature[0:120]
	}
	buf := new(bytes.Buffer)
	buf.Write([]byte{0x03, 0x00})
	var packetLength uint16 = uint16(38 + len(signature))
	binary.Write(buf, binary.BigEndian, packetLength)
	var lengthIndicator uint8 = uint8(packetLength - 5)
	binary.Write(buf, binary.BigEndian, lengthIndicator)
	buf.Write([]byte{0xe0, 0x00, 0x00, 0x00, 0x00, 0x00})
	buf.Write([]byte("Cookie: mstshash=" + signature))
	buf.Write([]byte{0x0d, 0x0a})
	buf.Write([]byte{0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00})
	// fmt.Printf("%v\n", buf.Bytes())
	return buf.Bytes()
}

type ConfirmPDU struct {
	Version         uint8
	Reserved        uint8
	PacketLength    uint16
	LengthIndicator uint8
	Type_AND_CDT    uint8 // CDT + T-selector
	DestinationRef  uint16
	SourceRef       uint16
	ClassOptions    uint8
}

// \x03\0\0\t\x02\xf0\x
func ParseConnectionConfirm(buf []byte) (*ConfirmPDU, error) {
	pdu := &ConfirmPDU{}
	// 校验前 4 字节 tpktHeader
	if len(buf) < 11 {
		return nil, errors.New("confirm pdu 校验失败")
	}
	err := binary.Read(bytes.NewBuffer(buf[0:1]), binary.BigEndian, &pdu.Version)
	if err != nil || pdu.Version != 0x3 {
		return nil, errors.New("version 校验失败")
	}
	binary.Read(bytes.NewBuffer(buf[1:2]), binary.BigEndian, &pdu.Reserved)
	if err != nil || pdu.Reserved != 0x0 {
		return nil, errors.New("reserved 校验失败")
	}
	binary.Read(bytes.NewBuffer(buf[2:4]), binary.BigEndian, &pdu.PacketLength)
	if err != nil || int(pdu.PacketLength) != len(buf) {
		return nil, errors.New("packet length 校验失败")
	}
	// 校验 7 字节 x224Ccf
	binary.Read(bytes.NewBuffer(buf[4:5]), binary.BigEndian, &pdu.LengthIndicator)
	if err != nil || pdu.LengthIndicator+5 != uint8(pdu.PacketLength) {
		return nil, errors.New("length indicator 校验失败")
	}
	binary.Read(bytes.NewBuffer(buf[5:6]), binary.BigEndian, &pdu.Type_AND_CDT)
	if err != nil || pdu.Type_AND_CDT != 0xd0 {
		// CC (1101 0000)
		return nil, errors.New("type 校验失败")
	}
	err = binary.Read(bytes.NewBuffer(buf[6:8]), binary.BigEndian, &pdu.DestinationRef)
	if err != nil {
		return nil, err
	}
	err = binary.Read(bytes.NewBuffer(buf[8:10]), binary.BigEndian, &pdu.SourceRef)
	if err != nil {
		return nil, err
	}
	err = binary.Read(bytes.NewBuffer(buf[10:11]), binary.BigEndian, &pdu.ClassOptions)
	if err != nil || (pdu.ClassOptions != 0x00 && pdu.ClassOptions != 0x02) {
		// 正常为0000，扩展为0010
		return nil, errors.New("class options 校验失败")
	}
	// todo. 校验可选的后 8 字节
	return pdu, nil
}

type Challenge_Message struct {
	Signature              string
	MessageType            uint32 //消息类型
	TargetNameLen          uint16
	TargetNameMaxLen       uint16
	TargetNameBufferOffset uint32
	NegotiateFlags         int32
	ServerChallenge        int64
	Reserved               int32
	TargetInfoLen          uint16
	TargetInfoMaxLen       uint16
	TargetInfoBufferOffset uint32
	ProductMajorVersion    uint8
	ProductMinorVersion    uint8
	ProductBuild           uint16
	// Reserved              3 byte
	NTLMRevisionCurrent uint8
}

// TargetInfo 是个存储 AV_PAIR 对象数组
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786
type MsvAv struct {
	AvId  uint16
	AvLen uint16
	Value string
}
type OSInfo struct {
	OS                    string
	DNS_Tree_Name         string
	System_Time           string
	DNS_Domain_Name       string
	DNS_Computer_Name     string
	NetBIOS_Computer_Name string
	NetBIOS_Domain_Name   string
	TargetName            string
	Product_Version       string
}

// 为跨平台, 参考 golang.org/x/sys/windows 实现
type Filetime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

func (ft *Filetime) Nanoseconds() int64 {
	// 100-nanosecond intervals since January 1, 1601
	nsec := int64(ft.HighDateTime)<<32 + int64(ft.LowDateTime)
	// change starting time to the Epoch (00:00:00 UTC, January 1, 1970)
	nsec -= 116444736000000000
	// convert into nanoseconds
	nsec *= 100
	return nsec
}

func FileTimeToSystemTime(t []byte) time.Time { // 输入是 8 字节
	ft := &Filetime{
		LowDateTime:  binary.LittleEndian.Uint32(t[:4]),
		HighDateTime: binary.LittleEndian.Uint32(t[4:]),
	}
	return time.Unix(0, ft.Nanoseconds())
}
func DetectOSInfo(host string, port int) (*OSInfo, error) {
	dialer := &net.Dialer{
		Timeout:   6 * time.Second,  // 设置连接超时时间
		KeepAlive: 15 * time.Second, // 设置心跳保活时间
	}
	conf := &tls.Config{
		// CipherSuites: []uint16{
		// tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		// tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		// tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		// tls.TLS_RSA_WITH_RC4_128_SHA,
		// tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		// tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		// },
		MinVersion:               tls.VersionTLS10,
		InsecureSkipVerify:       true,
		PreferServerCipherSuites: true,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", host, port), conf)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	/*
			    -- NTLMSSP Negotiate request mimicking a Windows 10 client
		    local NTLM_NEGOTIATE_BLOB = stdnse.fromhex(
		      "30 37 A0 03 02 01 60 A1 30 30 2E 30 2C A0 2A 04 28" ..
		      "4e 54 4c 4d 53 53 50 00" .. -- Signature - NTLMSSP
		      "01 00 00 00" ..  -- MessageType: 4 字节 - 01
		      "B7 82 08 E2 " .. -- NegotiateFlags (NEGOTIATE_SIGN_ALWAYS | NEGOTIATE_NTLM | NEGOTIATE_SIGN | REQUEST_TARGET | NEGOTIATE_UNICODE)
		      "00 00 " ..       -- DomainNameLen
		      "00 00" ..        -- DomainNameMaxLen
		      "00 00 00 00" ..  -- DomainNameBufferOffset
		      "00 00 " ..       -- WorkstationLen
		      "00 00" ..        -- WorkstationMaxLen
		      "00 00 00 00" ..  -- WorkstationBufferOffset
		      "0A" ..           -- ProductMajorVersion = 10
		      "00 " ..          -- ProductMinorVersion = 0
		      "63 45 " ..       -- ProductBuild = 0x4563 = 17763
		      "00 00 00" ..     -- Reserved
		      "0F"              -- NTLMRevision = 5 = NTLMSSP_REVISION_W2K3
		    )
	*/
	NTLM_NEGOTIATE_BLOB := []byte{
		0x30, 0x37, 0xA0, 0x03, 0x02, 0x01, 0x60, 0xA1, 0x30, 0x30, 0x2E, 0x30, 0x2C, 0xA0, 0x2A, 0x04, 0x28,
		0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
		0x01, 0x00, 0x00, 0x00,
		0xB7, 0x82, 0x08, 0xE2,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x0A,
		0x00,
		0x63, 0x45,
		0x00, 0x00, 0x00,
		0x0F,
	}
	_, err = conn.Write(NTLM_NEGOTIATE_BLOB)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		// 为什么 read 会报错 fmt.Printf("--- %v", err)
		return nil, err
	}
	recvStr := string(buf[:n])
	index := strings.Index(recvStr, "NTLMSSP")
	if index > -1 && n >= 56 { // 不包含 Payload 至少 56 字节
		bufChallenge := buf[index:n]
		challenge := &Challenge_Message{}
		challenge.Signature = string(bufChallenge[:7])
		err = binary.Read(bytes.NewBuffer(bufChallenge[8:12]), binary.LittleEndian, &challenge.MessageType)
		if err != nil || challenge.MessageType != 0x2 {
			return nil, errors.New("MessageType 校验失败")
		}
		err = binary.Read(bytes.NewBuffer(bufChallenge[12:14]), binary.LittleEndian, &challenge.TargetNameLen)
		if err != nil || challenge.TargetNameLen%2 != 0 {
			// the values of TargetNameBufferOffset and TargetNameLen MUST be multiples of 2.
			return nil, errors.New("TargetNameLen 校验失败")
		}
		err = binary.Read(bytes.NewBuffer(bufChallenge[14:16]), binary.LittleEndian, &challenge.TargetNameMaxLen)
		if err != nil {
			return nil, errors.New("TargetNameMaxLen 校验失败")
		}
		err = binary.Read(bytes.NewBuffer(bufChallenge[16:20]), binary.LittleEndian, &challenge.TargetNameBufferOffset)
		if err != nil || challenge.TargetInfoBufferOffset%2 != 0 {
			// the values of TargetNameBufferOffset and TargetNameLen MUST be multiples of 2.
			return nil, errors.New("TargetNameBufferOffset 校验失败")
		}

		err = binary.Read(bytes.NewBuffer(bufChallenge[20:24]), binary.LittleEndian, &challenge.NegotiateFlags)
		if err != nil {
			return nil, errors.New("NegotiateFlags 校验失败")
		}
		err = binary.Read(bytes.NewBuffer(bufChallenge[24:32]), binary.LittleEndian, &challenge.ServerChallenge)
		if err != nil {
			return nil, errors.New("ServerChallenge 校验失败")
		}
		err = binary.Read(bytes.NewBuffer(bufChallenge[32:40]), binary.LittleEndian, &challenge.Reserved)
		if err != nil || challenge.Reserved != 0x0 {
			return nil, errors.New("reserved 校验失败")
		}
		err = binary.Read(bytes.NewBuffer(bufChallenge[40:42]), binary.LittleEndian, &challenge.TargetInfoLen)
		if err != nil {
			return nil, errors.New("TargetInfoLen 校验失败")
		}
		err = binary.Read(bytes.NewBuffer(bufChallenge[42:44]), binary.LittleEndian, &challenge.TargetInfoMaxLen)
		if err != nil {
			return nil, errors.New("TargetInfoMaxLen 校验失败")
		}
		err = binary.Read(bytes.NewBuffer(bufChallenge[44:48]), binary.LittleEndian, &challenge.TargetInfoBufferOffset)
		if err != nil {
			return nil, errors.New("TargetInfoBufferOffset 校验失败")
		}
		err = binary.Read(bytes.NewBuffer(bufChallenge[48:49]), binary.LittleEndian, &challenge.ProductMajorVersion)
		if err != nil {
			return nil, errors.New("ProductMajorVersion 校验失败")
		}
		err = binary.Read(bytes.NewBuffer(bufChallenge[49:50]), binary.LittleEndian, &challenge.ProductMinorVersion)
		if err != nil {
			return nil, errors.New("ProductMinorVersion 校验失败")
		}
		err = binary.Read(bytes.NewBuffer(bufChallenge[50:52]), binary.LittleEndian, &challenge.ProductBuild)
		if err != nil {
			return nil, errors.New("ProductBuild 校验失败")
		}
		osinfo := &OSInfo{
			Product_Version: fmt.Sprintf("%d.%d.%d", challenge.ProductMajorVersion, challenge.ProductMinorVersion, challenge.ProductBuild),
		}
		if value, ok := OSVerMapv2[osinfo.Product_Version]; ok {
			osinfo.OS = value
		} else if value, ok := OSVerMapv2[fmt.Sprintf("%d.%d", challenge.ProductMajorVersion, challenge.ProductMinorVersion)]; ok {
			osinfo.OS = value
		}
		if challenge.TargetNameLen > 0 && int(challenge.TargetNameLen)+int(challenge.TargetNameBufferOffset) <= n {
			osinfo.TargetName = strings.Map(func(r rune) rune {
				if unicode.IsGraphic(r) {
					return r
				}
				return -1
			}, string(bufChallenge[challenge.TargetNameBufferOffset:int(challenge.TargetNameLen)+int(challenge.TargetNameBufferOffset)]))
		}
		if challenge.TargetInfoLen > 0 && int(challenge.TargetInfoLen)+int(challenge.TargetInfoBufferOffset) <= n {
			targetInfoBuf := bufChallenge[challenge.TargetInfoBufferOffset : int(challenge.TargetInfoLen)+int(challenge.TargetInfoBufferOffset)]
			cursor := 0
			for cursor+4 <= int(challenge.TargetInfoLen) {
				// 循环提取 avpair
				avpair := &MsvAv{}
				err = binary.Read(bytes.NewBuffer(targetInfoBuf[cursor:cursor+2]), binary.LittleEndian, &avpair.AvId)
				if err != nil {
					return nil, errors.New("AV_PAIR 结构体校验失败")
				}
				err = binary.Read(bytes.NewBuffer(targetInfoBuf[cursor+2:cursor+4]), binary.LittleEndian, &avpair.AvLen)
				if err != nil {
					return nil, errors.New("AV_PAIR 结构体校验失败")
				}
				// 存在部分不可见字符的情况
				visibleChars := strings.Map(func(r rune) rune {
					if unicode.IsGraphic(r) {
						return r
					}
					return -1
				}, string(targetInfoBuf[cursor+4:cursor+4+int(avpair.AvLen)]))
				switch avpair.AvId {
				case 0x0001:
					osinfo.NetBIOS_Computer_Name = visibleChars
				case 0x0002:
					osinfo.NetBIOS_Domain_Name = visibleChars
				case 0x0003:
					osinfo.DNS_Computer_Name = visibleChars
				case 0x0004:
					osinfo.DNS_Domain_Name = visibleChars
				case 0x0005:
					osinfo.DNS_Tree_Name = visibleChars
				case 0x0006:
				case 0x0007:
					if avpair.AvLen != 8 {
						return nil, errors.New("AV_PAIR 结构体校验失败")
					}
					t := FileTimeToSystemTime(targetInfoBuf[cursor+4 : cursor+4+8])
					osinfo.System_Time = t.Format("2006-01-02 15:04:05")
				case 0x0008:
				case 0x0009:
				case 0x000A:
				case 0x0000:
					return osinfo, nil
				default:
					// err = binary.Read(bytes.NewBuffer(targetInfoBuf[cursor:cursor+2]), binary.LittleEndian, &avpair.AvId)
					// fmt.Printf("%d %d %d", cursor, n, avpair.AvId)
					return nil, errors.New("AV_PAIR 结构体校验失败")
				}
				// 更新 cursor
				cursor = cursor + 4 + int(avpair.AvLen)
			}
		}
		return osinfo, nil
	}
	return nil, errors.New("Challenge Message 校验失败")
}
