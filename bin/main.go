package main

import (
	cloudca "github.com/cloud-ca/docker-machine-driver-cloudca"
	"github.com/docker/machine/libmachine/drivers/plugin"
)

func main() {
	plugin.RegisterDriver(cloudca.NewDriver("", ""))
}
