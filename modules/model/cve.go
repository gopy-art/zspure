package model

type cve string

var CVE cve 

func (cve) MainResource() string { return "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%v" }