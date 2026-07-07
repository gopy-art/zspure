package pop3

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
	"zspure/modules/model"
)

type Pop3Scanning struct {
	IP     net.IP     `json:"ip,omitempty"`
	Port   int        `json:"port,omitempty"`
	Status string     `json:"status,omitempty"`
	Banner pop3Banner `json:"banner,omitempty"`

	Description     string `json:"description,omitempty"`
	DetectionPacket []byte `json:"detection_packet,omitempty"`
	BannerPacket    []byte `json:"banner_packet,omitempty"`
}

type pop3Banner struct {
	Banner string `json:"banner"`
	Sha256 string `json:"sha256"`
}

func (p *Pop3Scanning) PrintInfo() {
	fmt.Println(p.Description)
}

func (p *Pop3Scanning) SetDescription() {
	p.Description = "POP3 (Post Office Protocol version 3) is an email protocol that downloads emails from a mail server to your local device and typically deletes them from the server."
}

func (p *Pop3Scanning) SetAddress(ip net.IP, port int) {
	p.IP = ip
	p.Port = port
}

func (p *Pop3Scanning) SetDetectionPacket(packet []byte) {
	if len(packet) == 0 || packet == nil {
		p.DetectionPacket = []byte("HELP\r\n")
	} else {
		p.DetectionPacket = packet
	}
}

func (p *Pop3Scanning) SetBannerPacket(packet []byte) {
	if len(packet) == 0 || packet == nil {
		p.BannerPacket = []byte("\r\n")
	} else {
		p.BannerPacket = packet
	}
}

func (p *Pop3Scanning) ServiceDetection(conn *net.Conn) (bool, error) {
	if _, err := (*conn).Write(p.DetectionPacket); err != nil {
		return false, fmt.Errorf("Write error: %v", err)
	}
	response := make([]byte, 4096)
	n, err := (*conn).Read(response)
	if err != nil {
		return false, fmt.Errorf("Read error: %v", err)
	}
	if VerifyPOP3Contents(string(response[:n])) {
		p.Banner.Banner = strings.TrimSuffix(string(response[:n]), "\r\n")
		hash := sha256.Sum256(response[:n])
		p.Banner.Sha256 = hex.EncodeToString(hash[:])
		p.Status = "success"
		return true, nil
	}
	p.Status = "failed"
	return false, nil
}

func (p *Pop3Scanning) BannerGathering(conn *net.Conn) (bool, error) {
	/*
		The IMAP protocol is none probe and with the first packet it will give us the informatiom that we want, so in this protocol the ServiceDetection will do everything
	*/
	return true, nil
}

func (p *Pop3Scanning) PrintResult() model.ScanStructure {
	return model.ScanStructure{
		IP: p.IP,
		Data: model.ScanDataStructure{
			Status:    p.Status,
			Protocol:  "pop3",
			Port:      p.Port,
			Result:    p.Banner,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}
}
