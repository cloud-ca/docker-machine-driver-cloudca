package cloudca

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"

	"github.com/cloud-ca/go-cloudca"
	"github.com/cloud-ca/go-cloudca/api"
	"github.com/cloud-ca/go-cloudca/services/cloudca"
	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/ssh"
	"github.com/docker/machine/libmachine/state"
)

const (
	driverName            = "cloudca"
	defaultSSHUser        = "cca-user"
	dockerPort            = 2376
	swarmPort             = 3376
	userDataToMountVolume = `#cloud-config
fs_setup:
   - label:  data
     filesystem: 'ext4'
     device: '/dev/xvdb'
mounts:
  - [ xvdb, /var/lib/docker, "ext4", "defaults", "0", "0" ]
coreos:
  units:
    - name: format-datavolume.service
      command: start
      content: |
        [Unit]
        Description=Formats the data volume
        After=dev-xvdb.device
        Requires=dev-xvdb.device
        ConditionPathExists=!/var/lib/docker.btrfs
        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStart=/usr/sbin/mkfs.btrfs /dev/xvdb
        ExecStart=/usr/bin/mkdir /var/lib/docker.btrfs
    - name: var-lib-docker.mount
      command: start
      content: |
        [Unit]
        Description=Mount data volume to /var/lib/docker
        Requires=format-datavolume.service
        After=format-datavolume.service
        [Mount]
        What=/dev/xvdb
        Where=/var/lib/docker
        Type=btrfs
    - name: docker.service
      drop-ins:
        - name: 10-wait-docker.conf
          content: |
            [Unit]
            After=var-lib-docker.mount
            Requires=var-lib-docker.mount
`
)

type configError struct {
	option string
}

func (e *configError) Error() string {
	return fmt.Sprintf("cloudca driver requires the --cloudca-%s option", e.option)
}

type Driver struct {
	*drivers.BaseDriver
	Id                       string
	ApiUrl                   string
	ApiKey                   string
	ServiceCode              string
	EnvironmentName          string
	UsePrivateIp             bool
	PublicIp                 string
	PublicIpId               string
	PrivateIp                string
	PrivateIpId              string
	TemplateId               string
	ComputeOfferingId        string
	CpuCount                 string
	MemoryInMb               string
	NetworkId                string
	VpcId                    string
	RootDiskSizeInGb         string
	AdditionalDiskOfferingId string
	AdditionalDiskSizeGb     string
	AdditionalDiskIops       string
	AdditionalVolumeId       string
}

// GetCreateFlags registers the flags this driver adds to
// "docker hosts create"
func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			Name:   "cloudca-api-url",
			Usage:  "cloud.ca API URL",
			EnvVar: "CLOUDCA_API_URL",
			Value:  "https://api.cloud.ca/v1",
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
			Name:   "cloudca-template",
			Usage:  "cloud.ca template name or ID",
			EnvVar: "CLOUDCA_TEMPLATE",
		},
		mcnflag.StringFlag{
			Name:   "cloudca-compute-offering",
			Usage:  "cloud.ca compute offering name or ID",
			EnvVar: "CLOUDCA_COMPUTE_OFFERING",
		},
		mcnflag.StringFlag{
			Name:   "cloudca-cpu-count",
			Usage:  "cloud.ca CPU count for custom compute offerings",
			EnvVar: "CLOUDCA_CPU_COUNT",
		},
		mcnflag.StringFlag{
			Name:   "cloudca-memory-mb",
			Usage:  "cloud.ca memory in MB for custom compute offerings",
			EnvVar: "CLOUDCA_MEMORY_MB",
		},
		mcnflag.StringFlag{
			Name:   "cloudca-root-disk-size-in-gb",
			Usage:  "cloud.ca root disk size in GB (for resizable templates)",
			EnvVar: "CLOUDCA_ROOT_DISK_SIZE_GB",
		},
		mcnflag.StringFlag{
			Name:   "cloudca-additional-disk-offering",
			Usage:  "cloud.ca additional disk offering name or ID to attach to the machine",
			EnvVar: "CLOUDCA_ADDITIONAL_DISK_OFFERING",
		},
		mcnflag.StringFlag{
			Name:   "cloudca-additional-disk-size-gb",
			Usage:  "cloud.ca additional disk size in GB (for custom disk offerings)",
			EnvVar: "CLOUDCA_ADDITIONAL_DISK_SIZE_GB",
		},
		mcnflag.StringFlag{
			Name:   "cloudca-additional-disk-iops",
			Usage:  "cloud.ca additional disk IOPS (for custom disk offerings)",
			EnvVar: "CLOUDCA_ADDITIONAL_DISK_IOPS",
		},
		mcnflag.StringFlag{
			Name:   "cloudca-network-id",
			Usage:  "cloud.ca network ID",
			EnvVar: "CLOUDCA_NETWORK_ID",
		},
		mcnflag.BoolFlag{
			Name:   "cloudca-use-private-ip",
			Usage:  "Use a private IP to access the machine",
			EnvVar: "CLOUDCA_USE_PRIVATE_IP",
		},
		mcnflag.StringFlag{
			Name:   "cloudca-ssh-user",
			Usage:  "cloud.ca SSH user",
			EnvVar: "CLOUDCA_SSH_USER",
			Value:  defaultSSHUser,
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
		d.SSHUser = defaultSSHUser
	}
	return d.SSHUser
}

// SetConfigFromFlags configures the driver with the object that was returned
// by RegisterCreateFlags
func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.ApiUrl = flags.String("cloudca-api-url")
	d.ApiKey = flags.String("cloudca-api-key")
	d.ServiceCode = flags.String("cloudca-service-code")
	d.EnvironmentName = flags.String("cloudca-environment-name")

	d.UsePrivateIp = flags.Bool("cloudca-use-private-ip")
	d.SSHUser = flags.String("cloudca-ssh-user")

	if err := d.setTemplate(flags.String("cloudca-template")); err != nil {
		return err
	}
	if err := d.setComputeOffering(flags.String("cloudca-compute-offering")); err != nil {
		return err
	}
	d.CpuCount = flags.String("cloudca-cpu-count")
	d.MemoryInMb = flags.String("cloudca-memory-mb")
	d.RootDiskSizeInGb = flags.String("cloudca-root-disk-size-in-gb")

	if err := d.setNetwork(flags.String("cloudca-network-id")); err != nil {
		return err
	}

	if err := d.setAdditionalDiskOffering(flags.String("cloudca-additional-disk-offering")); err != nil {
		return err
	}
	d.AdditionalDiskSizeGb = flags.String("cloudca-additional-disk-size-gb")
	d.AdditionalDiskIops = flags.String("cloudca-additional-disk-iops")

	d.SwarmMaster = flags.Bool("swarm-master")
	d.SwarmDiscovery = flags.String("swarm-discovery")

	if d.ApiKey == "" {
		return &configError{option: "api-key"}
	}

	if d.ServiceCode == "" {
		return &configError{option: "service-code"}
	}

	if d.EnvironmentName == "" {
		return &configError{option: "environment-name"}
	}

	if d.TemplateId == "" {
		return &configError{option: "template"}
	}

	if d.ComputeOfferingId == "" {
		return &configError{option: "compute-offering"}
	}

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
	if d.UsePrivateIp {
		return d.PrivateIp, nil
	}
	return d.PublicIp, nil
}

// GetState returns the state that the host is in (running, stopped, etc)
func (d *Driver) GetState() (state.State, error) {
	log.Info("Getting state of the cloud.ca instance...")
	ccaClient := d.getClient()
	instance, err := ccaClient.Instances.Get(d.Id)
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
	case "Rebooting":
		return state.Stopped, nil
	case "Shutdowned":
		return state.Stopped, nil
	case "Migrating":
		return state.Paused, nil
	case "Error":
		return state.Error, nil
	case "Unknown":
		return state.Error, nil
	}

	return state.None, nil
}

// PreCreate allows for pre-create operations to make sure a driver is ready for creation
func (d *Driver) PreCreateCheck() error {
	ccaClient := d.getClient()
	computeOffering, cerr := ccaClient.ComputeOfferings.Get(d.ComputeOfferingId)
	if cerr != nil {
		return cerr
	}

	hasCustomComputeOfferingFields := false
	if d.CpuCount != "" || d.MemoryInMb != "" {
		hasCustomComputeOfferingFields = true
	}

	if !computeOffering.Custom && hasCustomComputeOfferingFields {
		return fmt.Errorf("Cannot have a CPU count or memory in MB because \"%s\" isn't a custom compute offering", computeOffering.Name)
	}
	if computeOffering.Custom && !hasCustomComputeOfferingFields {
		return fmt.Errorf("The CPU count and memory in MB are required because \"%s\" is a custom compute offering", computeOffering.Name)
	}

	if d.AdditionalDiskOfferingId != "" {
		diskOffering, cerr := ccaClient.DiskOfferings.Get(d.AdditionalDiskOfferingId)
		if cerr != nil {
			return cerr
		}

		if !diskOffering.CustomSize && d.AdditionalDiskSizeGb != "" {
			return fmt.Errorf("Cannot have a Size in GB \"%s\" isn't a custom size disk offering", diskOffering.Name)
		}
		if !diskOffering.CustomIops && d.AdditionalDiskIops != "" {
			return fmt.Errorf("Cannot have a IOPS value because \"%s\" isn't a custom IOPS disk offering", diskOffering.Name)
		}
		if diskOffering.CustomSize && d.AdditionalDiskSizeGb == "" {
			return fmt.Errorf("The additional size in GB is required because \"%s\" is a custom size disk offering", diskOffering.Name)
		}
		if diskOffering.CustomIops && d.AdditionalDiskIops == "" {
			return fmt.Errorf("The IOPS value is required because \"%s\" is a custom IOPS disk offering", diskOffering.Name)
		}
	}

	return nil
}

// Create a host using the driver's config
func (d *Driver) Create() error {

	key, err := d.createSshKey()
	if err != nil {
		return err
	}

	// !! Workaround for MC-7431.
	key = strings.TrimSpace(key)
	key = fmt.Sprintf("%s %s", key, d.MachineName)
	// !! End workaround for MC-7431.

	instanceToCreate := cloudca.Instance{
		Name:              d.MachineName,
		ComputeOfferingId: d.ComputeOfferingId,
		TemplateId:        d.TemplateId,
		NetworkId:         d.NetworkId,
		PublicKey:         key,
		SSHKeyName:        d.MachineName,
	}

	if d.CpuCount != "" {
		cpucount, _ := strconv.Atoi(d.CpuCount)
		instanceToCreate.CpuCount = cpucount
	}
	if d.MemoryInMb != "" {
		memory, _ := strconv.Atoi(d.MemoryInMb)
		instanceToCreate.MemoryInMB = memory
	}
	if d.RootDiskSizeInGb != "" {
		rootDiskSizeInGb, err := strconv.Atoi(d.RootDiskSizeInGb)
		if err != nil {
			return err
		}
		instanceToCreate.RootVolumeSizeInGb = rootDiskSizeInGb
	}
	if d.AdditionalDiskOfferingId != "" {
		instanceToCreate.UserData = userDataToMountVolume
		instanceToCreate.AdditionalDiskOfferingId = d.AdditionalDiskOfferingId
		instanceToCreate.AdditionalDiskSizeInGb = d.AdditionalDiskSizeGb
		instanceToCreate.AdditionalDiskIops = d.AdditionalDiskIops
	}

	ccaClient := d.getClient()
	newInstance, err := ccaClient.Instances.Create(instanceToCreate)
	if err != nil {
		return fmt.Errorf("Error creating the new instance %s: %s", instanceToCreate.Name, err)
	}

	d.Id = newInstance.Id
	d.PrivateIp = newInstance.IpAddress
	d.PrivateIpId = newInstance.IpAddressId
	d.setAdditionalVolumeId()

	if !d.UsePrivateIp {
		if d.PublicIpId == "" {
			if err := d.acquirePublicIP(); err != nil {
				return err
			}
		}

		if err := d.configurePortForwardingRules(); err != nil {
			return err
		}
	}

	return nil
}

func (d *Driver) Remove() error {
	if err := d.releasePublicIP(); err != nil {
		if ccaErr, ok := err.(api.CcaErrorResponse); ok && ccaErr.StatusCode == 404 {
			log.Info("Public IP was not found, assuming it was already deleted...")
		} else {
			return err
		}
	}

	volumeIdsToDelete := []string{}
	if d.AdditionalVolumeId != "" {
		volumeIdsToDelete = []string{d.AdditionalVolumeId}
	}
	ccaClient := d.getClient()
	if _, err := ccaClient.Instances.DestroyWithOptions(d.Id, cloudca.DestroyOptions{PurgeImmediately: true, VolumeIdsToDelete: volumeIdsToDelete}); err != nil {
		if ccaErr, ok := err.(api.CcaErrorResponse); ok && ccaErr.StatusCode == 404 {
			log.Info("Instance was not found, assuming it was already deleted...")
		} else {
			return err
		}
	}

	return nil
}

func (d *Driver) Start() (err error) {
	vmstate, err := d.GetState()
	if err != nil {
		return err
	}

	if vmstate == state.Running {
		log.Info("Machine is already running")
		return nil
	}

	if vmstate == state.Starting {
		log.Info("Machine is already starting")
		return nil
	}

	ccaClient := d.getClient()
	if _, err = ccaClient.Instances.Start(d.Id); err != nil {
		return err
	}

	return nil
}

func (d *Driver) Stop() (err error) {
	vmstate, err := d.GetState()
	if err != nil {
		return err
	}

	if vmstate == state.Stopped {
		log.Info("Machine is already stopped")
		return nil
	}

	ccaClient := d.getClient()
	if _, err = ccaClient.Instances.Stop(d.Id); err != nil {
		return err
	}

	return nil
}

func (d *Driver) Restart() (err error) {
	vmstate, err := d.GetState()
	if err != nil {
		return err
	}

	if vmstate == state.Stopped {
		return fmt.Errorf("Machine is stopped, use start command to start it")
	}

	ccaClient := d.getClient()
	if _, err = ccaClient.Instances.Reboot(d.Id); err != nil {
		return err
	}

	return nil
}

func (d *Driver) Kill() (err error) {
	return d.Stop()
}

func (d *Driver) getClient() cloudca.Resources {
	ccaClient := cca.NewCcaClientWithURL(d.ApiUrl, d.ApiKey)
	resources, _ := ccaClient.GetResources(d.ServiceCode, d.EnvironmentName)
	return resources.(cloudca.Resources)
}

func (d *Driver) setTemplate(template string) error {
	if isID(template) {
		d.TemplateId = template
		log.Debugf("template id: %q", d.TemplateId)
		return nil
	}

	if template == "" {
		return nil
	}

	ccaClient := d.getClient()
	templates, err := ccaClient.Templates.List()
	if err != nil {
		return fmt.Errorf("Unable to list templates: %v", err)
	}
	for _, currentTpl := range templates {

		if strings.EqualFold(template, currentTpl.Name) {
			d.TemplateId = currentTpl.Id
			log.Debugf("template id: %q", d.TemplateId)
		}
	}

	return nil
}

func (d *Driver) setComputeOffering(computeOffering string) error {
	if isID(computeOffering) {
		d.ComputeOfferingId = computeOffering
		log.Debugf("compute offering id: %q", d.ComputeOfferingId)
		return nil
	}

	if computeOffering == "" {
		return nil
	}

	ccaClient := d.getClient()
	computeOfferings, err := ccaClient.ComputeOfferings.List()
	if err != nil {
		return err
	}
	for _, offering := range computeOfferings {

		if strings.EqualFold(offering.Name, computeOffering) {
			d.ComputeOfferingId = offering.Id
			log.Debugf("Found compute offering: %+v", offering)
		}
	}

	return nil
}

func (d *Driver) setAdditionalDiskOffering(diskOffering string) error {
	if isID(diskOffering) {
		d.AdditionalDiskOfferingId = diskOffering
		log.Debugf("Additional disk offering id: %q", d.AdditionalDiskOfferingId)
		return nil
	}

	if diskOffering == "" {
		return nil
	}

	ccaClient := d.getClient()
	diskOfferings, err := ccaClient.DiskOfferings.List()
	if err != nil {
		return err
	}
	for _, offering := range diskOfferings {

		if strings.EqualFold(offering.Name, diskOffering) {
			d.AdditionalDiskOfferingId = offering.Id
			log.Debugf("Found disk offering: %+v", offering)
		}
	}

	return nil
}

func (d *Driver) setNetwork(networkId string) error {
	d.NetworkId = networkId

	ccaClient := d.getClient()
	network, err := ccaClient.Networks.Get(networkId)
	if err != nil {
		return err
	}
	d.VpcId = network.VpcId

	return nil
}

func (d *Driver) setAdditionalVolumeId() error {
	ccaClient := d.getClient()
	volumes, err := ccaClient.Volumes.ListOfType("data")
	if err != nil {
		return err
	}
	for _, volume := range volumes {
		if strings.EqualFold(volume.InstanceId, d.Id) {
			d.AdditionalVolumeId = volume.Id
			log.Debugf("Found additional volume ID: %+v", volume.Id)
			break
		}
	}

	return nil
}

func (d *Driver) acquirePublicIP() error {
	log.Info("Acquiring public ip address...")
	publicIpToCreate := cloudca.PublicIp{
		VpcId: d.VpcId,
	}
	ccaClient := d.getClient()
	newPublicIp, err := ccaClient.PublicIps.Acquire(publicIpToCreate)
	if err != nil {
		return fmt.Errorf("Error acquiring the new public ip %s", err)
	}
	d.PublicIpId = newPublicIp.Id
	d.PublicIp = newPublicIp.IpAddress

	return nil
}

func (d *Driver) releasePublicIP() error {
	if d.PublicIpId == "" {
		// No public IP to free - keep on keepin on.
		return nil
	}
	log.Info("Releasing public ip address...")
	ccaClient := d.getClient()
	_, err := ccaClient.PublicIps.Release(d.PublicIpId)
	return err
}

func (d *Driver) configurePortForwardingRule(publicPort, privatePort int) error {
	pfr := cloudca.PortForwardingRule{
		PublicIpId:       d.PublicIpId,
		Protocol:         "TCP",
		PublicPortStart:  strconv.Itoa(publicPort),
		PrivateIpId:      d.PrivateIpId,
		PrivatePortStart: strconv.Itoa(privatePort),
	}
	ccaClient := d.getClient()
	_, err := ccaClient.PortForwardingRules.Create(pfr)
	if err != nil {
		return err
	}

	return nil
}

func (d *Driver) configurePortForwardingRules() error {
	log.Infof("Creating port forwarding rules...")
	log.Info("Creating port forwarding rule for ssh port ...")
	if err := d.configurePortForwardingRule(22, 22); err != nil {
		return err
	}

	log.Info("Creating port forwarding rule for docker port ...")
	if err := d.configurePortForwardingRule(dockerPort, dockerPort); err != nil {
		return err
	}

	if d.SwarmMaster {
		log.Info("Creating port forwarding rule for swarm port ...")
		if err := d.configurePortForwardingRule(swarmPort, swarmPort); err != nil {
			return err
		}
	}

	return nil
}

func isID(id string) bool {
	re := regexp.MustCompile(`^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
	return re.MatchString(id)
}

func (d *Driver) createSshKey() (string, error) {
	sshKeyPath := d.ResolveStorePath("id_rsa")
	if err := ssh.GenerateSSHKey(sshKeyPath); err != nil {
		return "", err
	}
	key, err := ioutil.ReadFile(sshKeyPath + ".pub")
	if err != nil {
		return "", err
	}
	return string(key), nil
}
