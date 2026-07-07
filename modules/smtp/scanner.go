package smtp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
	"zspure/modules/model"
)

type SmtpScanning struct {
	IP     net.IP     `json:"ip,omitempty"`
	Port   int        `json:"port,omitempty"`
	Status string     `json:"status,omitempty"`
	Banner smtpBanner `json:"banner,omitempty"`

	Description     string `json:"description,omitempty"`
	DetectionPacket []byte `json:"detection_packet,omitempty"`
	BannerPacket    []byte `json:"banner_packet,omitempty"`
}

type smtpBanner struct {
	Banner string `json:"banner"`
	Sha256 string `json:"sha256"`
}

func (s *SmtpScanning) PrintInfo() {
	fmt.Println(s.Description)
}

func (s *SmtpScanning) SetDescription() {
	s.Description = "SMTP (Simple Mail Transfer Protocol) is the protocol used for sending emails from a client to a server, and between mail servers."
}

func (s *SmtpScanning) SetAddress(ip net.IP, port int) {
	s.IP = ip
	s.Port = port
}

func (s *SmtpScanning) SetDetectionPacket(packet []byte) {
	if len(packet) == 0 || packet == nil {
		s.DetectionPacket = []byte("HELP\r\n")
	} else {
		s.DetectionPacket = packet
	}
}

func (s *SmtpScanning) SetBannerPacket(packet []byte) {
	if len(packet) == 0 || packet == nil {
		s.BannerPacket = []byte("\r\n")
	} else {
		s.BannerPacket = packet
	}
}

func (s *SmtpScanning) ServiceDetection(conn *net.Conn) (bool, error) {
	if _, err := (*conn).Write(s.DetectionPacket); err != nil {
		return false, fmt.Errorf("Write error: %v", err)
	}
	response := make([]byte, 4096)
	n, err := (*conn).Read(response)
	if err != nil {
		return false, fmt.Errorf("Read error: %v", err)
	}
	if VerifySMTPContents(string(response[:n])) {
		s.Banner.Banner = strings.TrimSuffix(string(response[:n]), "\r\n")
		hash := sha256.Sum256(response[:n])
		s.Banner.Sha256 = hex.EncodeToString(hash[:])
		s.Status = "success"
		return true, nil
	}
	s.Status = "failed"
	return false, nil
}

func (s *SmtpScanning) BannerGathering(conn *net.Conn) (bool, error) {
	/*
		The SMTP protocol is none probe and with the first packet it will give us the informatiom that we want, so in this protocol the ServiceDetection will do everything
	*/
	return true, nil
}

func (s *SmtpScanning) PrintResult() model.ScanStructure {
	return model.ScanStructure{
		IP: s.IP,
		Data: model.ScanDataStructure{
			Status:    s.Status,
			Protocol:  "smtp",
			Port:      s.Port,
			Result:    s.Banner,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}
}
