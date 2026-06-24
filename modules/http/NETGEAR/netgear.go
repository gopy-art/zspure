package netgear

import (
	"fmt"
	"strconv"
	"strings"
	"zspure/config"
	"zspure/config/cmd"
	"zspure/handler"
	"zspure/modules/model"
	"zspure/utils"

	"github.com/PuerkitoBio/goquery"
)

type NETGEAR struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (n *NETGEAR) SetCategory(category ...string) {
	n.Category = model.Category.Switch()
}

func (n *NETGEAR) SetDeviceName(device ...string) {
	n.DeviceName = "NETGEAR"
}

func (a *NETGEAR) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "<TITLE>NETGEAR S3300-52X-PoE+</TITLE>"},
		{"result.response.body": "<img width=\"138\" alt=\"Netgear\" src=\"/base/images/Netgear-logo.png\">"},
	}
}

func (n *NETGEAR) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if (strings.Contains(val.(string), "<TITLE>NETGEAR S3300-52X-PoE+</TITLE>") &&
			strings.Contains(val.(string), "<img width=\"138\" alt=\"Netgear\" src=\"/base/images/Netgear-logo.png\">")) &&
			!strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			!strings.Contains(val.(string), "<p hidden>") {
			return true
		}
	}
	return false
}

func (n *NETGEAR) DeviceScan(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	n.ExtraInformation.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			n.ExtraInformation.SetExtraInfo("server", server[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			n.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(val.(string)))
		if err != nil {
			return false
		}

		// Find the `TAG:label CLASS:productName` and get its text it will include version
		text := doc.Find("label.productName").Text()
		words := strings.Fields(text)

		if len(words) >= 10 {
			n.Version = words[0]
			return true
		}
	}
	return false
}

func (n *NETGEAR) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{"cve.descriptions.value": fmt.Sprintf("%s %s", n.DeviceName, n.Version)}))
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
		url := fmt.Sprintf(model.CVE.MainResource(),
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v %v", n.DeviceName, n.Version), " ", "%20")))
		recieve, err := utils.GatherCVEOnline(url)
		if err != nil {
			cmd.ErrorLogger.Println("[CVE] error in gather the CVE for this device. (Server error)")
			return
		}
		CVE = append(CVE, recieve...)
	}

	if len(CVE) == 0 {
		cmd.InfoLogger.Println("[CVE] do not find any CVE for this module.")
		return
	}

	for _, v := range CVE {
		n.CveList = append(n.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	n.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if n.CveScore > 7 {
		n.Sensibility = "HIGH"
	} else if n.CveScore >= 4 && n.CveScore <= 7 {
		n.Sensibility = "MEDIUM"
	} else if n.CveScore < 4 {
		n.Sensibility = "LOW"
	}
	n.CveList = utils.RemoveDuplicates(n.CveList)
}

func (n *NETGEAR) PrintInfo() string { return model.Category.Switch() + " | NETGEAR" }

func (n *NETGEAR) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         n.Category,
		DeviceName:       n.DeviceName,
		Version:          n.Version,
		CveList:          n.CveList,
		Sensibility:      n.Sensibility,
		CveScore:         n.CveScore,
		ExtraInformation: n.ExtraInformation,
	}
}
