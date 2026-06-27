package tls

import (
	"fmt"
	"net"
	"zspure/modules/model"
)

type TLSScanning struct {
	IP     net.IP `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"`
	Banner string `json:"banner,omitempty"`
	Sha256 string `json:"sha_256,omitempty"`

	Description     string `json:"description,omitempty"`
	DetectionPacket []byte `json:"detection_packet,omitempty"`
	BannerPacket    []byte `json:"banner_packet,omitempty"`
}

func (t *TLSScanning) PrintInfo() {
	fmt.Println(t.Description)
}

func (t *TLSScanning) SetDescription() {
	t.Description = "TLS (Transport Layer Security) is a cryptographic protocol designed to provide secure communication over a computer network."
}

func (t *TLSScanning) SetAddress(ip net.IP, port int)                {}
func (t *TLSScanning) SetDetectionPacket(packet []byte)              {}
func (t *TLSScanning) SetBannerPacket(packet []byte)                 {}
func (t *TLSScanning) ServiceDetection(conn *net.Conn) (bool, error) { return false, nil }
func (t *TLSScanning) BannerGathering(conn *net.Conn) (bool, error)  { return false, nil }
func (t *TLSScanning) PrintResult() model.ScanStructure              { return model.ScanStructure{} }