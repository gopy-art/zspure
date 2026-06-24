package model

import (
	"encoding/json"
	"fmt"
	"zspure/handler"
)

type ModuleMethods interface {
	SetCategory(category ...string)
	SetDeviceName(device ...string)
	Filters(banner map[string]interface{}) bool
	Patterns() []map[string]interface{}
	DeviceScan(banner map[string]interface{}) bool
	CveScan(els *handler.Elastic)
	PrintInfo() string
	Result() ModuleStructure
}

type ModuleExtraInfo map[string]interface{}

type ModuleStructure struct {
	Category         string          `json:"dvs_category,omitempty"`
	DeviceName       string          `json:"device_name,omitempty"`
	Version          string          `json:"version,omitempty"`
	CveList          []string        `json:"cves,omitempty"`
	Sensibility      string          `json:"base_severity,omitempty"`
	CveScore         float64         `json:"cve_score,omitempty"`
	ExtraInformation ModuleExtraInfo `json:"dvs_extra,omitempty"`
}

type CVEStructure struct {
	CVEID        string  `json:"cve_id"`
	Description  string  `json:"description"`
	BaseScore    float64 `json:"base_score"`
	BaseSeverity string  `json:"base_severity"`
}

type GatherModuleSructure struct {
	ID       string         `json:"id"`
	Index    string         `json:"index"`
	IP       string         `json:"ip"`
	Port     float64        `json:"port"`
	Protocol string         `json:"protocol"`
	Banner   map[string]any `json:"banner"`
}

func NewModuleStructure(data map[string]any) GatherModuleSructure {
	return GatherModuleSructure{
		ID:       data["_id"].(string),
		Index:    data["_index"].(string),
		IP:       data["ip"].(string),
		Port:     data["port"].(float64),
		Protocol: data["protocol"].(string),
		Banner:   data["result"].(map[string]any),
	}
}

func (m *ModuleExtraInfo) NewExtraInfo() {
	*m = make(ModuleExtraInfo)
}

func (m *ModuleExtraInfo) GetExtraInfo() map[string]interface{} {
	return *m
}

func (m *ModuleExtraInfo) SetExtraInfo(key, value string) {
	(*m)[key] = value
}

func (m *ModuleExtraInfo) PrintExtraInfo() error {
	buf, err := json.Marshal(*m)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", buf)
	return nil
}

func NewCVEStructure(data map[string]any) CVEStructure {
	var description, baseSeverity string
	var baseScore float64
	for _, v := range data["cve"].(map[string]any)["descriptions"].([]interface{}) {
		if v.(map[string]interface{})["lang"] == "en" {
			description = v.(map[string]interface{})["value"].(string)
		}
	}

	if val, ok := data["cve"].(map[string]any)["metrics"].(map[string]any)["cvssMetricV31"]; ok {
		baseScore = val.([]any)[0].(map[string]any)["cvssData"].(map[string]any)["baseScore"].(float64)
	} else if val, ok := data["cve"].(map[string]any)["metrics"].(map[string]any)["cvssMetricV30"]; ok {
		baseScore = val.([]any)[0].(map[string]any)["cvssData"].(map[string]any)["baseScore"].(float64)
	} else if val, ok := data["cve"].(map[string]any)["metrics"].(map[string]any)["cvssMetricV2"]; ok {
		baseScore = val.([]any)[0].(map[string]any)["cvssData"].(map[string]any)["baseScore"].(float64)
	}

	if val, ok := data["cve"].(map[string]any)["metrics"].(map[string]any)["cvssMetricV31"]; ok {
		baseSeverity = val.([]any)[0].(map[string]any)["cvssData"].(map[string]any)["baseSeverity"].(string)
	} else if val, ok := data["cve"].(map[string]any)["metrics"].(map[string]any)["cvssMetricV30"]; ok {
		baseSeverity = val.([]any)[0].(map[string]any)["cvssData"].(map[string]any)["baseSeverity"].(string)
	} else if val, ok := data["cve"].(map[string]any)["metrics"].(map[string]any)["cvssMetricV31"]; ok {
		baseSeverity = val.([]any)[0].(map[string]any)["cvssData"].(map[string]any)["baseSeverity"].(string)
	}

	return CVEStructure{
		CVEID:        data["cve"].(map[string]any)["id"].(string),
		Description:  description,
		BaseScore:    baseScore,
		BaseSeverity: baseSeverity,
	}
}
