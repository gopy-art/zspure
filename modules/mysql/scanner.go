package mysql

import (
	"fmt"
	"net"
	"zspure/modules/model"
)

type MysqlScanning struct {
	IP     net.IP `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"`
	Status string    `json:"status,omitempty"`
	Banner string `json:"banner,omitempty"`
	Sha256 string `json:"sha_256,omitempty"`

	Description     string `json:"description,omitempty"`
	DetectionPacket []byte `json:"detection_packet,omitempty"`
	BannerPacket    []byte `json:"banner_packet,omitempty"`
}

func (m *MysqlScanning) PrintInfo() {
	fmt.Println(m.Description)
}

func (m *MysqlScanning) SetDescription() {
	m.Description = "The MySQL protocol is an application-layer protocol used for communication between MySQL clients and servers."
}

func (m *MysqlScanning) SetAddress(ip net.IP, port int)                {}
func (m *MysqlScanning) SetDetectionPacket(packet []byte)              {}
func (m *MysqlScanning) SetBannerPacket(packet []byte)                 {}
func (m *MysqlScanning) ServiceDetection(conn *net.Conn) (bool, error) { return false, nil }
func (m *MysqlScanning) BannerGathering(conn *net.Conn) (bool, error)  { return false, nil }
func (m *MysqlScanning) PrintResult() model.ScanStructure              { return model.ScanStructure{} }