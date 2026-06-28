package modbus

import (
	"fmt"
	"net"
	"zspure/modules/model"
)

type ModbusScanning struct {
	IP     net.IP `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"`
	Status string    `json:"status,omitempty"`
	Banner string `json:"banner,omitempty"`
	Sha256 string `json:"sha_256,omitempty"`

	Description     string `json:"description,omitempty"`
	DetectionPacket []byte `json:"detection_packet,omitempty"`
	BannerPacket    []byte `json:"banner_packet,omitempty"`
}

func (m *ModbusScanning) PrintInfo() {
	fmt.Println(m.Description)
}

func (m *ModbusScanning) SetDescription() {
	m.Description = "Modbus is a serial communication protocol originally developed by Modicon in 1979 for use with programmable logic controllers (PLCs)."
}

func (m *ModbusScanning) SetAddress(ip net.IP, port int)                {}
func (m *ModbusScanning) SetDetectionPacket(packet []byte)              {}
func (m *ModbusScanning) SetBannerPacket(packet []byte)                 {}
func (m *ModbusScanning) ServiceDetection(conn *net.Conn) (bool, error) { return false, nil }
func (m *ModbusScanning) BannerGathering(conn *net.Conn) (bool, error)  { return false, nil }
func (m *ModbusScanning) PrintResult() model.ScanStructure              { return model.ScanStructure{} }