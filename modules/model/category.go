package model

type category string

var Category category

func (category) Firewall() string       { return "Firewall" }
func (category) Router() string         { return "Router" }
func (category) Service() string        { return "Service" }
func (category) NetworkStorage() string { return "Network Storage" }
func (category) Industrial() string     { return "Industrial" }
func (category) Electric() string       { return "Electrical" }
func (category) Printer() string        { return "Printer" }
func (category) Camera() string         { return "Camera" }
func (category) Device() string         { return "Device" }
func (category) Server() string         { return "Server" }
func (category) Database() string       { return "Datebase" }
func (category) Controller() string     { return "Controller" }
func (category) VPN() string            { return "VPN" }
func (category) Proxy() string          { return "Proxy" }
func (category) Monitoring() string     { return "Monitoring" }
func (category) Switch() string         { return "Switch" }
func (category) WebServer() string      { return "Web Server" }
func (category) AccessPoint() string    { return "AccessPoint" }
func (category) Modem() string          { return "Modem" }
func (category) Network() string        { return "Network Device" }
func (category) Gateway() string        { return "Gateway" }
