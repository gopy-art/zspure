package config

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	LOGIC       string = ""
	APP_VERSION string = "1.2.0"
	CONFIG_PATH string = ""
	ORDER       string = "desc"
	CLEAR       string = ""
	TAG         string = ""
	KEY         string = ""
	INPUTFILE   string = ""
	URL         string = ""
	FIND_CVE    bool
	STDIN_INPUT bool
	ZGRAB_INPUT bool
	JSON_OUTPUT bool
	Vtoggle     bool
	BatchSize   int
)

var Root = &cobra.Command{
	Use:   "zspure",
	Short: "fast and efficient device and cve scanner in golang",
	Long:  `This tool is fast and efficient scanner/banner gathering/fingerprints tools in one!`,
	Run: func(cmd *cobra.Command, args []string) {
		if Vtoggle {
			fmt.Println(APP_VERSION)
			os.Exit(0)
		}
	},
}

type Config struct {
	ElasticIndices []string `json:"elk_indices" yaml:"elk_indices"`
	ElasticUrl     []string `json:"elk_url" yaml:"elk_url"`
	Devices        []string `json:"device" yaml:"device"`
	ElasticApiKey  string   `json:"elk_key" yaml:"elk_key"`
	IndexOfCVE     string   `json:"cve_index" yaml:"cve_index"`
}

func ParseConfig(filepath string) (*Config, error) {
	var conf *Config = new(Config)
	if filepath == "" {
		return nil, fmt.Errorf("file config path should not be empty")
	}

	buf, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(buf, &conf); err != nil {
		return nil, err
	}
	if len(conf.ElasticIndices) == 0 {
		return nil, fmt.Errorf("the config file is empty")
	}
	return conf, nil
}
