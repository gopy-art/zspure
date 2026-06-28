package http

import (
	"fmt"
	"net"
	"zspure/modules/model"
)

type HttpScanning struct {
	IP     net.IP `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"`
	Status string    `json:"status,omitempty"`
	Banner string `json:"banner,omitempty"`
	Sha256 string `json:"sha_256,omitempty"`

	Description     string `json:"description,omitempty"`
	DetectionPacket []byte `json:"detection_packet,omitempty"`
	BannerPacket    []byte `json:"banner_packet,omitempty"`
}

func (h *HttpScanning) PrintInfo() {
	fmt.Println(h.Description)
}

func (h *HttpScanning) SetDescription() {
	h.Description = "HTTP (Hypertext Transfer Protocol) is a client-server protocol for transferring hypermedia documents (like HTML) over the internet."
}

func (h *HttpScanning) SetAddress(ip net.IP, port int)                {}
func (h *HttpScanning) SetDetectionPacket(packet []byte)              {}
func (h *HttpScanning) SetBannerPacket(packet []byte)                 {}
func (h *HttpScanning) ServiceDetection(conn *net.Conn) (bool, error) { return false, nil }
func (h *HttpScanning) BannerGathering(conn *net.Conn) (bool, error)  { return false, nil }
func (h *HttpScanning) PrintResult() model.ScanStructure              { return model.ScanStructure{} }
