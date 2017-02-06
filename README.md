# docker-machine-cloudca
Create Docker machines on [cloud.ca](https://cloud.ca)

You need to get your **cloud.ca API key** from the cloud.ca portal through the _API keys_ option under the _user profile menu_ and pass that to `docker-machine create` with the `--cloudca-api-key` option.

## Requirements

* Install [Docker Machine](https://docs.docker.com/machine/install-machine/)
* Install [Go](https://golang.org/doc/install)

## Installation

1. Download the cloud.ca Docker Machine driver binary for your OS from the [releases page](https://github.com/cloud-ca/docker-machine-driver-cloudca/releases).
2. Copy the driver to the directory where Docker Machine is located.

## Usage

```bash
docker-machine create -d cloudca \
   --cloudca-api-key "APIkey****************" \
   --cloudca-service-code "compute-qc" \
   --cloudca-environment-name "test-area" \
   --cloudca-template "Ubuntu 16.04.01 HVM" \
   --cloudca-compute-offering "1vCPU.1GB" \
   --cloudca-network-id "bbefe8dd-bb3e-4f37-b467-b63f8334c15b" \
   --cloudca-additional-disk-offering "50GB - 50 IOPS Min." \
   test-machine1
```
**Notes:**
* It is recommended to use Environment variables to store sensitive information like API keys. See the options below for the list of supported variables.
* The cloud.ca instances have limited disk space on their root volumes. In order to get more disk space for your Docker machines, use the `--cloudca-additional-disk-offering` option to specify an additional volume that Docker will be able to use.

## Options

|Option Name|Environment Variable Name|Description|Default Value|required|
|---|---|---|---|---|
|``--cloudca-api-key``         |``CLOUDCA_API_KEY``         |cloud.ca API key  |none      |yes|
|``--cloudca-service-code``    |``CLOUDCA_SERVICE_CODE``    |cloud.ca service code   |none      |yes|
|``--cloudca-environment-name``|``CLOUDCA_ENVIRONMENT_NAME``|cloud.ca environment name      |none      |yes|
|``--cloudca-template``        |``CLOUDCA_TEMPLATE``        |cloud.ca template name or ID      |none      |yes|
|``--cloudca-compute-offering``|``CLOUDCA_COMPUTE_OFFERING``|cloud.ca compute offering name or ID|none      |yes|
|``--cloudca-network-id``      |``CLOUDCA_NETWORK_ID``      |cloud.ca network ID (where the machine will be deployed)|none     |yes|
|``--cloudca-additional-disk-offering``|``CLOUDCA_ADDITIONAL_DISK_OFFERING``|cloud.ca additional disk offering name or ID to attach to the machine|none     |no|
|``--cloudca-use-private-ip``  |``CLOUDCA_USE_PRIVATE_IP``  |Use a private IP to access the machine|false |no|
|``--cloudca-ssh-user``        |``CLOUDCA_SSH_USER``        |cloud.ca SSH user|cca-user|no|

## Build from source

Download the driver source:

```bash
$ go get github.com/cloud-ca/docker-machine-driver-cloudca
```

Compile the driver:

```bash
$ cd $GOPATH/src/github.com/cloud-ca/docker-machine-driver-cloudca
$ make install
```

## License

This project is licensed under the terms of the MIT license.
