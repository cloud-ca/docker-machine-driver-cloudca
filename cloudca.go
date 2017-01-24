package cloudca

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/cloud-ca/go-cloudca"
	"github.com/cloud-ca/go-cloudca/services/cloudca"
	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/state"
)

const (
	driverName = "cloudca"
	dockerPort = 2376
	swarmPort  = 3376
)

type configError struct {
	option string
}

func (e *configError) Error() string {
	return fmt.Sprintf("cloudca driver requires the --cloudca-%s option", e.option)
}

type Driver struct {
	*drivers.BaseDriver
	Id                   string
	APIURL               string
	APIKey               string
	ServiceCode          string
	EnvironmentName      string
	UsePrivateIP         bool
	UsePortForward       bool
	PublicIP             string
	PublicIPID           string
	DisassociatePublicIP bool
	SSHKeyPair           string
	PrivateIP            string
	Purge                bool
	Template             string
	TemplateID           string
	ComputeOffering      string
	ComputeOfferingID    string
	CpuCount             string
	MemoryInMb           string
	NetworkID            string
	UserDataFile         string
	UserData             string
}

// GetCreateFlags registers the flags this driver adds to
// "docker hosts create"
func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			Name:   "cloudca-api-url",
			Usage:  "cloud.ca API URL",
			EnvVar: "CLOUDCA_API_URL",
		},
		mcnflag.StringFlag{
			Name:   "cloudca-api-key",
			Usage:  "cloud.ca API key",
			EnvVar: "CLOUDCA_API_KEY",
		},
		mcnflag.StringFlag{
			Name:   "cloudca-service-code",
			Usage:  "cloud.ca service code",
			EnvVar: "CLOUDCA_SERVICE_CODE",
		},
		mcnflag.StringFlag{
			Name:   "cloudca-environment-name",
			Usage:  "cloud.ca environment name",
			EnvVar: "CLOUDCA_ENVIRONMENT_NAME",
		},
		mcnflag.StringFlag{
			Name:  "cloudca-template",
			Usage: "cloud.ca template",
		},
		mcnflag.StringFlag{
			Name:  "cloudca-compute-offering",
			Usage: "cloud.ca compute offering",
		},
		mcnflag.StringFlag{
			Name:  "cloudca-cpu-count",
			Usage: "cloud.ca CPU count for custom compute offerings",
		},
		mcnflag.StringFlag{
			Name:  "cloudca-memory-mb",
			Usage: "cloud.ca memory in MB for custom compute offerings",
		},
		mcnflag.StringFlag{
			Name:  "cloudca-network-id",
			Usage: "cloud.ca network ID",
		},
		mcnflag.BoolFlag{
			Name:  "cloudca-use-private-address",
			Usage: "Use a private IP to access the machine",
		},
		mcnflag.BoolFlag{
			Name:  "cloudca-use-port-forward",
			Usage: "Use port forwarding rule to access the machine",
		},
		mcnflag.StringFlag{
			Name:  "cloudca-public-ip",
			Usage: "cloud.ca Public IP",
		},
		mcnflag.StringFlag{
			Name:  "cloudca-ssh-user",
			Usage: "cloud.ca SSH user",
			Value: "cca-user",
		},
		mcnflag.BoolFlag{
			Name:  "cloudca-purge",
			Usage: "Whether or not to purge the machine upon removal",
		},
		mcnflag.StringFlag{
			Name:  "cloudca-userdata-file",
			Usage: "cloud.ca Userdata file",
		},
	}
}

func NewDriver(hostName, storePath string) drivers.Driver {

	driver := &Driver{
		BaseDriver: &drivers.BaseDriver{
			MachineName: hostName,
			StorePath:   storePath,
		},
	}
	return driver
}

// DriverName returns the name of the driver as it is registered
func (d *Driver) DriverName() string {
	return driverName
}

func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

func (d *Driver) GetSSHUsername() string {
	if d.SSHUser == "" {
		d.SSHUser = "cca-user"
	}
	return d.SSHUser
}

// SetConfigFromFlags configures the driver with the object that was returned
// by RegisterCreateFlags
func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.APIURL = flags.String("cloudca-api-url")
	d.APIKey = flags.String("cloudca-api-key")
	d.ServiceCode = flags.String("cloudca-service-code")
	d.EnvironmentName = flags.String("cloudca-environment-name")
	d.NetworkID = flags.String("cloudca-network-id")
	d.UsePrivateIP = flags.Bool("cloudca-use-private-address")
	d.UsePortForward = flags.Bool("cloudca-use-port-forward")
	d.SSHUser = flags.String("cloudca-ssh-user")
	d.Purge = flags.Bool("cloudca-purge")
	d.CpuCount = flags.String("cloudca-cpu-count")
	d.MemoryInMb = flags.String("cloudca-memory-mb")

	if err := d.setTemplate(flags.String("cloudca-template")); err != nil {
		return err
	}
	if err := d.setComputeOffering(flags.String("cloudca-compute-offering")); err != nil {
		return err
	}
	// if err := d.setNetwork(flags.String("cloudca-network")); err != nil {
	// 	return err
	// }
	// if err := d.setPublicIP(flags.String("cloudca-public-ip")); err != nil {
	// 	return err
	// }
	// if err := d.setUserData(flags.String("cloudca-userdata-file")); err != nil {
	// 	return err
	// }

	d.SwarmMaster = flags.Bool("swarm-master")
	d.SwarmDiscovery = flags.String("swarm-discovery")

	d.SSHKeyPair = d.MachineName

	if d.APIURL == "" {
		return &configError{option: "api-url"}
	}

	if d.APIKey == "" {
		return &configError{option: "api-key"}
	}

	if d.ServiceCode == "" {
		return &configError{option: "service-code"}
	}

	if d.EnvironmentName == "" {
		return &configError{option: "environment-name"}
	}

	if d.Template == "" {
		return &configError{option: "template"}
	}

	if d.ComputeOffering == "" {
		return &configError{option: "compute-offering"}
	}

	d.DisassociatePublicIP = false

	return nil
}

// GetURL returns a Docker compatible host URL for connecting to this host
// e.g. tcp://1.2.3.4:2376
func (d *Driver) GetURL() (string, error) {
	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("tcp://%s:%d", ip, dockerPort), nil
}

// GetIP returns the IP that this host is available at
func (d *Driver) GetIP() (string, error) {
	if d.UsePrivateIP {
		return d.PrivateIP, nil
	}
	return d.PublicIP, nil
}

// GetState returns the state that the host is in (running, stopped, etc)
func (d *Driver) GetState() (state.State, error) {
	ccaClient := d.getClient()
	resources, _ := ccaClient.GetResources(d.ServiceCode, d.EnvironmentName)
	ccaResources := resources.(cloudca.Resources)

	instance, err := ccaResources.Instances.Get(d.Id)
	if err != nil {
		return state.Error, err
	}

	switch instance.State {
	case "Starting":
		return state.Starting, nil
	case "Running":
		return state.Running, nil
	case "Stopping":
		return state.Running, nil
	case "Stopped":
		return state.Stopped, nil
	case "Destroyed":
		return state.Stopped, nil
	case "Expunging":
		return state.Stopped, nil
	case "Migrating":
		return state.Paused, nil
	case "Error":
		return state.Error, nil
	case "Unknown":
		return state.Error, nil
	case "Shutdowned":
		return state.Stopped, nil
	}

	return state.None, nil
}

// PreCreate allows for pre-create operations to make sure a driver is ready for creation
func (d *Driver) PreCreateCheck() error {
	//
	// if err := d.checkKeyPair(); err != nil {
	// 	return err
	// }
	//
	// if err := d.checkInstance(); err != nil {
	// 	return err
	// }

	return nil
}

// Create a host using the driver's config
func (d *Driver) Create() error {
	ccaClient := d.getClient()
	resources, _ := ccaClient.GetResources(d.ServiceCode, d.EnvironmentName)
	ccaResources := resources.(cloudca.Resources)

	instanceToCreate := cloudca.Instance{Name: d.MachineName,
		ComputeOfferingId: d.ComputeOfferingID,
		TemplateId:        d.TemplateID,
		NetworkId:         d.NetworkID,
	}

	/*if sshKeyname, ok := d.GetOk("ssh_key_name"); ok {
	     instanceToCreate.SSHKeyName = sshKeyname.(string)
	  }
	  if publicKey, ok := d.GetOk("public_key"); ok {
	     instanceToCreate.PublicKey = publicKey.(string)
	  }*/
	if d.UserData != "" {
		instanceToCreate.UserData = d.UserData
	}

	// hasCustomFields := false
	// if d.CpuCount, ok := d.GetOk("cpu_count"); ok {
	//    instanceToCreate.CpuCount = cpuCount.(int)
	//    hasCustomFields = true
	// }
	// if d.MemoryInMB, ok := d.GetOk("memory_in_mb"); ok {
	//    instanceToCreate.MemoryInMB = memoryInMB.(int)
	//    hasCustomFields = true
	// }

	// computeOffering, cerr := ccaResources.ComputeOfferings.Get(d.ComputeOfferingId)
	// if cerr != nil {
	//    return cerr
	// } else if !computeOffering.Custom && hasCustomFields {
	//    return fmt.Errorf("Cannot have a CPU count or memory in MB because \"%s\" isn't a custom compute offering", computeOffering.Name)
	// }

	newInstance, err := ccaResources.Instances.Create(instanceToCreate)
	if err != nil {
		return fmt.Errorf("Error creating the new instance %s: %s", instanceToCreate.Name, err)
	}

	d.Id = newInstance.Id
	d.PrivateIP = newInstance.IpAddress

	// if !d.UsePrivateIP {
	// 	if d.PublicIPID == "" {
	// 		if err := d.acquirePublicIP(); err != nil {
	// 			return err
	// 		}
	// 	}
	//
	// 	if d.UsePortForward {
	// 		if err := d.configurePortForwardingRules(); err != nil {
	// 			return err
	// 		}
	// 	} else {
	// 		if err := d.enableStaticNat(); err != nil {
	// 			return err
	// 		}
	// 	}
	//}

	return nil
}

func (d *Driver) Remove() error {
	return fmt.Errorf("Removing machines is not implemented yet")
}

func (d *Driver) Restart() (err error) {
	return fmt.Errorf("Restarting machines is not implemented yet")
}

// Start (STUB) start machine
func (d *Driver) Start() (err error) {
	return fmt.Errorf("Starting machines is not implemented yet")
}

// Stop (STUB) stop machine
func (d *Driver) Stop() (err error) {
	return fmt.Errorf("Stopping machines is not implemented yet")
}

func (d *Driver) Kill() (err error) {
	return fmt.Errorf("Killing machines is not implemented yet")
}

func (d *Driver) getClient() *cca.CcaClient {
	return cca.NewCcaClientWithURL(d.APIURL, d.APIKey)
}

func (d *Driver) setTemplate(template string) error {
	if isID(template) {
		d.TemplateID = template
		log.Debugf("template id: %q", d.TemplateID)
		return nil
	}

	d.Template = template
	d.TemplateID = ""
	if d.Template == "" {
		return nil
	}

	ccaClient := d.getClient()
	resources, _ := ccaClient.GetResources(d.ServiceCode, d.EnvironmentName)
	ccaResources := resources.(cloudca.Resources)

	log.Debugf("resources: %v", resources)

	templates, err := ccaResources.Templates.List()
	if err != nil {
		return fmt.Errorf("Unable to list templates: %v", err)
	}
	for _, currentTpl := range templates {

		if strings.EqualFold(template, currentTpl.Name) {
			d.TemplateID = currentTpl.Id
			log.Debugf("template id: %q", d.TemplateID)
		}
	}

	return nil
}

func (d *Driver) setComputeOffering(computeOffering string) error {
	if isID(computeOffering) {
		d.ComputeOfferingID = computeOffering
		log.Debugf("compute offering id: %q", d.ComputeOfferingID)
		return nil
	}

	d.ComputeOffering = computeOffering
	d.ComputeOfferingID = ""
	if d.ComputeOffering == "" {
		return nil
	}

	ccaClient := d.getClient()
	resources, _ := ccaClient.GetResources(d.ServiceCode, d.EnvironmentName)
	ccaResources := resources.(cloudca.Resources)

	computeOfferings, err := ccaResources.ComputeOfferings.List()
	if err != nil {
		return err
	}
	for _, offering := range computeOfferings {

		if strings.EqualFold(offering.Name, computeOffering) {
			d.ComputeOfferingID = offering.Id
			log.Debugf("Found compute offering: %+v", offering)
		}
	}

	return nil
}

func isID(id string) bool {
	re := regexp.MustCompile(`^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
	return re.MatchString(id)
}
