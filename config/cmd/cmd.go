package cmd

import (
	"os"
	"zspure/config"

	"github.com/spf13/cobra"
)

func SetupFlags() {
	config.Root.PersistentFlags().StringVar(&config.CONFIG_PATH, "config", "", "set the config file path.")
	config.Root.PersistentFlags().BoolVar(&config.JSON_OUTPUT, "json", false, "enable this when you want the output as JSON format.")
	config.Root.Flags().BoolVarP(&config.Vtoggle, "version", "v", false, "zspure version")

	createGroups()
	config.Root.AddCommand(createElsCommand())
	config.Root.AddCommand(createPanelCommand())
	config.Root.AddCommand(createFileCommand())
	config.Root.AddCommand(createPrintInfoCommand())
	config.Root.AddCommand(createBannerCommand())

	customHelpTemplate := `{{.Long}}

General Options:
{{range .Commands}}{{if eq .GroupID "general"}}  {{.Name | printf "%-10s"}} {{.Short}}
{{end}}{{end}}
Input/Output Options:
{{range .Commands}}{{if eq .GroupID "io"}}  {{.Name | printf "%-10s"}} {{.Short}}
{{end}}{{end}}
Network Options:
{{range .Commands}}{{if eq .GroupID "network"}}  {{.Name | printf "%-10s"}} {{.Short}}
{{end}}{{end}}
Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}
`

	config.Root.SetHelpTemplate(customHelpTemplate)
	config.Root.SetUsageTemplate(customHelpTemplate)

	if err := config.Root.Execute(); err != nil {
		ErrorLogger.Println(err)
		os.Exit(1)
	}
}

/*
Create the groups of the commands in the Flags & Command line in terminal
*/
func createGroups() {
	config.Root.AddGroup(&cobra.Group{
		ID:    "network",
		Title: "Network Options:",
	})
	config.Root.AddGroup(&cobra.Group{
		ID:    "general",
		Title: "General Options:",
	})
	config.Root.AddGroup(&cobra.Group{
		ID:    "io",
		Title: "Input/Output Options:",
	})
}

/*
Create the Elastic search command with its flags and formats
*/
func createElsCommand() *cobra.Command {
	pattern := &cobra.Command{
		Use:   "elastic",
		Short: "input/output in the elastic search database",
		Long: `This command will work with elastic search database.
In this way that will get the banners and data from the indecies base on the config file,
and then put the result on the same indecies ! (update the record)`,
		GroupID: "io",
		Example: `zspure elastic --config config.yml --tag "TEST" --order asc -b 10000
zspure elastic --config config.yml --tag "TEST" --clear "value if match" --key "key to clear"`,
		Run: func(cmd *cobra.Command, args []string) {
			config.LOGIC = "execute"
		},
	}

	pattern.PersistentFlags().StringVar(&config.ORDER, "order", "desc", "set the order for getting the data. (desc, asc)")
	pattern.PersistentFlags().StringVar(&config.CLEAR, "clear", "", "set the 'word' for clear in elastic.")
	pattern.PersistentFlags().StringVar(&config.TAG, "tag", "", "set the 'word' for tag in elastic to gather.")
	pattern.PersistentFlags().StringVar(&config.KEY, "key", "", "set the 'word' for key in elastic to clear.")
	pattern.PersistentFlags().IntVarP(&config.BatchSize, "batch", "b", 500, "set the batch size for the query.")
	pattern.PersistentFlags().BoolVar(&config.FIND_CVE, "cve", false, "enable this flag to get CVE for the specific device and version")

	customHelpTemplate := `{{.Long}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}

{{if .Example}}Examples:
{{.Example}}{{end}}
`

	pattern.SetHelpTemplate(customHelpTemplate)
	pattern.SetUsageTemplate(customHelpTemplate)
	return pattern
}

/*
Create the Panel command with its flags and formats
*/
func createPanelCommand() *cobra.Command {
	pattern := &cobra.Command{
		Use:   "panel",
		Short: "detect the HTTP/HTTPS panels exist on the network/internet",
		Long: `This command will send the HTTP/HTTPS request to the target (base on the input).
Then will detect the response of HTTP/HTTPS services to see which device or service is behind the panel!`,
		GroupID: "network",
		Run: func(cmd *cobra.Command, args []string) {
			config.LOGIC = "url"
		},
	}

	pattern.PersistentFlags().StringVar(&config.URL, "url", "", "set the URL of the panel for detecting.")
	pattern.PersistentFlags().BoolVar(&config.FIND_CVE, "cve", false, "enable this flag to get CVE for the specific device and version")

	customHelpTemplate := `{{.Long}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}
`

	pattern.SetHelpTemplate(customHelpTemplate)
	pattern.SetUsageTemplate(customHelpTemplate)
	return pattern
}

/*
Create the File command with its flags and formats
*/
func createFileCommand() *cobra.Command {
	pattern := &cobra.Command{
		Use:   "file",
		Short: "identify the *.html and the Zgrab *.json output file",
		Long: `This command will detect some infomation about the file has been given as input.
It will work with *.html files and the Zgrab/Zgrab2 (*.json) output files! `,
		GroupID: "io",
		Run: func(cmd *cobra.Command, args []string) {
			config.LOGIC = "file"
		},
	}

	pattern.PersistentFlags().StringVar(&config.INPUTFILE, "file", "", "set the input file path to detect the device.")
	pattern.PersistentFlags().BoolVar(&config.ZGRAB_INPUT, "zgrab-input", false, "enable this flag if the file or stdin is zgrab output")
	pattern.PersistentFlags().BoolVar(&config.STDIN_INPUT, "stdin", false, "enable this flag when you want to pass the file content in stdin pipeline")
	pattern.PersistentFlags().BoolVar(&config.FIND_CVE, "cve", false, "enable this flag to get CVE for the specific device and version")

	customHelpTemplate := `{{.Long}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}
`

	pattern.SetHelpTemplate(customHelpTemplate)
	pattern.SetUsageTemplate(customHelpTemplate)
	return pattern
}

/*
Create the Banner command with its flags and formats
*/
func createBannerCommand() *cobra.Command {
	pattern := &cobra.Command{
		Use:   "banner",
		Short: "scan and fingerprints the IP/CIDR in offline/online networks",
		Long: `This command will scan and fingerprints the IP/CIDR address given as input.
It just detects the protocols that tools support! (for see the protocols use the flag --show-protocols in banner command) `,
		GroupID: "network",
		Run: func(cmd *cobra.Command, args []string) {
			config.LOGIC = "banner"
		},
	}

	customHelpTemplate := `{{.Long}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}
`

	pattern.SetHelpTemplate(customHelpTemplate)
	pattern.SetUsageTemplate(customHelpTemplate)
	return pattern
}

/*
Create the Print info command with its flags and formats
*/
func createPrintInfoCommand() *cobra.Command {
	pattern := &cobra.Command{
		Use:     "info",
		Short:   "show devices/services in zspure",
		Long:    `This command will show the name and information about the devices/services written in this tool! `,
		GroupID: "general",
		Run: func(cmd *cobra.Command, args []string) {
			config.LOGIC = "print"
		},
	}

	pattern.PersistentFlags().BoolVar(&config.PROTOCOL_INFO, "protocols", false, "protocols information")
	pattern.PersistentFlags().BoolVar(&config.DEVICE_INFO, "devices", false, "devices/services information")

	customHelpTemplate := `{{.Long}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}
`

	pattern.SetHelpTemplate(customHelpTemplate)
	pattern.SetUsageTemplate(customHelpTemplate)
	return pattern
}
