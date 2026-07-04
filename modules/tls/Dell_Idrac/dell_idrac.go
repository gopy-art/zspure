package dellidrac

import (
	"fmt"
	"strconv"
	"strings"
	"zspure/config"
	"zspure/config/cmd"
	"zspure/handler"
	"zspure/modules/model"
	"zspure/utils"
)

type DellIdrac struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (d *DellIdrac) SetCategory(category ...string) {
	d.Category = model.Category.Controller()
}

func (d *DellIdrac) SetDeviceName(device ...string) {
	d.DeviceName = "Dell Idrac"
}

func (d *DellIdrac) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.issuer_dn": "Dell Inc."},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "idrac"},
	}
}

func (d *DellIdrac) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"].(string); ok {
		if strings.Contains(strings.ToLower(val), "dell inc.") && strings.Contains(strings.ToLower(val), "idrac") {
			return true
		}
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"].(string); ok {
		if strings.Contains(strings.ToLower(val), "dell inc.") && strings.Contains(strings.ToLower(val), "idrac") {
			return true
		}
	}
	return false
}

func (d *DellIdrac) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (d *DellIdrac) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": d.DeviceName,
		}))
		if len(result) == 0 {
			return
		}
		for _, c := range result {
			if len(CVE) == 10 {
				break
			}
			cveMod := model.NewCVEStructure(c)
			CVE = append(CVE, cveMod)
		}
	} else if config.FIND_CVE {
		url := fmt.Sprintf(model.CVE.MainResource(), "dell"+"%20"+"idrac")
		recieve, err := utils.GatherCVEOnline(url)
		if err != nil {
			cmd.ErrorLogger.Println("[CVE] error in gather the CVE for this device. (Server error)")
			return
		}
		CVE = append(CVE, recieve...)
	}

	d.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if d.CveScore > 7 {
		d.Sensibility = "HIGH"
	} else if d.CveScore >= 4 && d.CveScore <= 7 {
		d.Sensibility = "MEDIUM"
	} else if d.CveScore < 4 {
		d.Sensibility = "LOW"
	}
	d.CveList = utils.RemoveDuplicates(d.CveList)
}

func (d *DellIdrac) PrintInfo() string { return model.Category.Controller() + " | Dell Idrac" }

func (d *DellIdrac) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    d.Category,
		DeviceName:  d.DeviceName,
		Version:     d.Version,
		CveList:     d.CveList,
		Sensibility: d.Sensibility,
		CveScore:    d.CveScore,
	}
}
