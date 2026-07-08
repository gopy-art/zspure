package ssh

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
	"zspure/modules/model"
)

type SSHScanning struct {
	IP     net.IP    `json:"ip,omitempty"`
	Port   int       `json:"port,omitempty"`
	Status string    `json:"status,omitempty"`
	Banner sshBanner `json:"banner,omitempty"`

	Description     string `json:"description,omitempty"`
	DetectionPacket []byte `json:"detection_packet,omitempty"`
	BannerPacket    []byte `json:"banner_packet,omitempty"`
}

type sshBanner struct {
	ServerID map[string]interface{} `json:"server_id"`
	Sha256   string                 `json:"sha256"`
}

func (s *SSHScanning) PrintInfo() {
	fmt.Println(s.Description)
}

func (s *SSHScanning) SetDescription() {
	s.Description = "SSH (Secure Shell) is a cryptographic network protocol for secure remote access and command execution over unsecured networks."
}

func (s *SSHScanning) SetAddress(ip net.IP, port int) {
	s.IP = ip
	s.Port = port
}

func (s *SSHScanning) SetDetectionPacket(packet []byte) {
	if len(packet) == 0 || packet == nil {
		s.DetectionPacket = []byte("SSH-2.0-GoClient\r\n")
	} else {
		s.DetectionPacket = packet
	}
}

func (s *SSHScanning) SetBannerPacket(packet []byte) {
	if len(packet) == 0 || packet == nil {
		s.BannerPacket = []byte("\r\n")
	} else {
		s.BannerPacket = packet
	}
}

func (s *SSHScanning) ServiceDetection(conn *net.Conn) (bool, error) {
	if _, err := (*conn).Write(s.DetectionPacket); err != nil {
		return false, fmt.Errorf("Write error: %v", err)
	}
	response := make([]byte, 4096)
	n, err := (*conn).Read(response)
	if err != nil {
		return false, fmt.Errorf("Read error: %v", err)
	}
	if isSSHBanner(string(response[:n])) {
		s.Banner.ServerID = make(map[string]interface{})
		s.Banner.ServerID["raw"] = strings.TrimSuffix(string(response[:n]), "\r\n")
		re := regexp.MustCompile(`SSH-([\d.]+)-`)
		matches := re.FindStringSubmatch(string(response[:n]))
		if len(matches) > 1 {
			s.Banner.ServerID["version"] = matches[1]
		}
		hash := sha256.Sum256(response[:n])
		s.Banner.Sha256 = hex.EncodeToString(hash[:])
		s.Status = "success"
		return true, nil
	}
	s.Status = "failed"
	return false, nil
}

func (s *SSHScanning) BannerGathering(conn *net.Conn) (bool, error) {
	/*
		The SSH protocol is none probe and with the first packet it will give us the informatiom that we want, so in this protocol the ServiceDetection will do everything
	*/
	return true, nil
}

func (s *SSHScanning) PrintResult() model.ScanStructure {
	return model.ScanStructure{
		IP: s.IP,
		Data: model.ScanDataStructure{
			Status:    s.Status,
			Protocol:  "ssh",
			Port:      s.Port,
			Result:    s.Banner,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}
}
