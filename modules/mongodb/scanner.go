package mongodb

import (
	"fmt"
	"net"
	"zspure/modules/model"
)

type MongoDBScanning struct {
	IP     net.IP `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"`
	Status string    `json:"status,omitempty"`
	Banner string `json:"banner,omitempty"`
	Sha256 string `json:"sha_256,omitempty"`

	Description     string `json:"description,omitempty"`
	DetectionPacket []byte `json:"detection_packet,omitempty"`
	BannerPacket    []byte `json:"banner_packet,omitempty"`
}

func (m *MongoDBScanning) PrintInfo() {
	fmt.Println(m.Description)
}

func (m *MongoDBScanning) SetDescription() {
	m.Description = "The core protocol that MongoDB uses for client-server communication is called the MongoDB Wire Protocol."
}

func (m *MongoDBScanning) SetAddress(ip net.IP, port int)                {}
func (m *MongoDBScanning) SetDetectionPacket(packet []byte)              {}
func (m *MongoDBScanning) SetBannerPacket(packet []byte)                 {}
func (m *MongoDBScanning) ServiceDetection(conn *net.Conn) (bool, error) { return false, nil }
func (m *MongoDBScanning) BannerGathering(conn *net.Conn) (bool, error)  { return false, nil }
func (m *MongoDBScanning) PrintResult() model.ScanStructure              { return model.ScanStructure{} }