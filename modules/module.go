package modules

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"zspure/modules/bacnet"
	"zspure/modules/codesys"
	"zspure/modules/enip"
	"zspure/modules/ftp"
	"zspure/modules/http"
	"zspure/modules/modbus"
	"zspure/modules/model"
	"zspure/modules/mongodb"
	"zspure/modules/mssql"
	"zspure/modules/mysql"
	"zspure/modules/ntp"
	"zspure/modules/pcworx"
	"zspure/modules/pptp"
	"zspure/modules/redis"
	"zspure/modules/ssh"
	"zspure/modules/tls"
	"zspure/modules/wago"
)

var (
	ModuleList []string = []string{
		"http",
		"bacnet",
		"enip",
		"mssql",
		"ntp",
		"pptp",
		"ssh",
		"wago",
		"codesys",
		"mongodb",
		"mysql",
		"redis",
		"pcworx",
		"tls",
		"modbus",
		"ftp",
	}
)

func NewModule(protocol string) ([]model.ModuleMethods, error) {
	switch protocol {
	case "http":
		return http.NewHTTP(), nil
	case "bacnet":
		return bacnet.NewBACNET(), nil
	case "enip":
		return enip.NewENIP(), nil
	case "mssql":
		return mssql.NewMSSQL(), nil
	case "modbus":
		return modbus.NewMODBUS(), nil
	case "ntp":
		return ntp.NewNTP(), nil
	case "pptp":
		return pptp.NewENIP(), nil
	case "ssh":
		return ssh.NewSSH(), nil
	case "wago":
		return wago.NewWAGO(), nil
	case "codesys":
		return codesys.NewCODESYS(), nil
	case "mongodb":
		return mongodb.NewMONGODB(), nil
	case "mysql":
		return mysql.NewMYSQL(), nil
	case "redis":
		return redis.NewRedis(), nil
	case "pcworx":
		return pcworx.NewPCWORX(), nil
	case "tls":
		return tls.NewTLS(), nil
	case "ftp":
		return ftp.NewFTP(), nil
	default:
		return nil, fmt.Errorf("protocol not supported")
	}
}

func PrintModuleDevices() {
	var TotalCount int = 0
	var categories map[string]int = make(map[string]int)
	for n, m := range ModuleList {
		fmt.Printf("%d) %v\n", n+1, m)
		if devices, err := NewModule(m); err == nil {
			for num, d := range devices {
				fmt.Printf("\t%d-%d) %v\n", n+1, num+1, d.PrintInfo())
				d.SetCategory()
				if _, ok := categories[d.Result().Category]; ok {
					categories[d.Result().Category]++
				} else {
					categories[d.Result().Category] = 1
				}
				TotalCount++
			}
		}
	}

	fmt.Println(strings.Repeat("-", 100))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w , "Category\tDevice/Service Count")
	for k,v := range categories {
		fmt.Fprintf(w, "%s\t%d\t\n", k, v )
	}
	fmt.Fprintf(w, "TOTAL\t%d\n" , TotalCount)
	w.Flush()
}
