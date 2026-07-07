package honeypot

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type Honeypot struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (h *Honeypot) SetCategory(category ...string) {
	h.Category = ""
}

func (h *Honeypot) SetDeviceName(device ...string) {
	h.DeviceName = "Honeypot"
}

func (a *Honeypot) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "0<!DOCTYPE html>"},
		{"result.response.body": "<p hidden>"},
	}
}

func (h *Honeypot) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if strings.Contains(val.(string), "0<!DOCTYPE html>") ||
			strings.Contains(val.(string), "<p hidden>") {
			return true
		}
	}
	return false
}

func (h *Honeypot) DeviceScan(banner map[string]interface{}) bool {
	h.ExtraInformation.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			h.ExtraInformation.SetExtraInfo("server", server[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			h.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
		}
	}
	return false
}

func (h *Honeypot) CveScan(els *handler.Elastic) {}
func (h *Honeypot) PrintInfo() string            { return "Honeypot" }
func (h *Honeypot) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         h.Category,
		DeviceName:       h.DeviceName,
		Version:          h.Version,
		CveList:          h.CveList,
		Sensibility:      h.Sensibility,
		CveScore:         h.CveScore,
		ExtraInformation: h.ExtraInformation,
	}
}
