package ssh

import (
	"fmt"
	"net"
	"zspure/modules/model"
)

type SSHScanning struct {
	IP     net.IP `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"`
	Status string    `json:"status,omitempty"`
	Banner string `json:"banner,omitempty"`
	Sha256 string `json:"sha_256,omitempty"`

	Description     string `json:"description,omitempty"`
	DetectionPacket []byte `json:"detection_packet,omitempty"`
	BannerPacket    []byte `json:"banner_packet,omitempty"`
}

func (s *SSHScanning) PrintInfo() {
	fmt.Println(s.Description)
}

func (s *SSHScanning) SetDescription() {
	s.Description = "SSH (Secure Shell) is a cryptographic network protocol for secure remote access and command execution over unsecured networks."
}

func (s *SSHScanning) SetAddress(ip net.IP, port int)                {}
func (s *SSHScanning) SetDetectionPacket(packet []byte)              {}
func (s *SSHScanning) SetBannerPacket(packet []byte)                 {}
func (s *SSHScanning) ServiceDetection(conn *net.Conn) (bool, error) { return false, nil }
func (s *SSHScanning) BannerGathering(conn *net.Conn) (bool, error)  { return false, nil }
func (s *SSHScanning) PrintResult() model.ScanStructure              { return model.ScanStructure{} }