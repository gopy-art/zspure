package redis

import (
	"fmt"
	"net"
	"zspure/modules/model"
)

type RedisScanning struct {
	IP     net.IP `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"`
	Banner string `json:"banner,omitempty"`
	Sha256 string `json:"sha_256,omitempty"`

	Description     string `json:"description,omitempty"`
	DetectionPacket []byte `json:"detection_packet,omitempty"`
	BannerPacket    []byte `json:"banner_packet,omitempty"`
}

func (r *RedisScanning) PrintInfo() {
	fmt.Println(r.Description)
}

func (r *RedisScanning) SetDescription() {
	r.Description = "RESP (REdis Serialization Protocol) is the application-layer protocol used by Redis for client-server communication."
}

func (r *RedisScanning) SetAddress(ip net.IP, port int)                {}
func (r *RedisScanning) SetDetectionPacket(packet []byte)              {}
func (r *RedisScanning) SetBannerPacket(packet []byte)                 {}
func (r *RedisScanning) ServiceDetection(conn *net.Conn) (bool, error) { return false, nil }
func (r *RedisScanning) BannerGathering(conn *net.Conn) (bool, error)  { return false, nil }
func (r *RedisScanning) PrintResult() model.ScanStructure              { return model.ScanStructure{} }