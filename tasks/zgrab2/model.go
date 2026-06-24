package zgrab2

import "encoding/json"

type ZgrabModel struct {
	IP   string                    `json:"ip"`
	Data map[string]zgrabDataModel `json:"data"`
}

type zgrabDataModel struct {
	Status    string                 `json:"status"`
	Protocol  string                 `json:"protocol"`
	Port      int                    `json:"port"`
	Result    map[string]interface{} `json:"result"`
	Timestamp string                 `json:"timestamp"`
}

func (z *ZgrabModel) Parse(data []byte) error {
	return json.Unmarshal(data, &z)
}