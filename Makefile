
default: build

init:
	curl https://glide.sh/get | sh
	glide install

build: clean
	glide up
	GOGC=off go build -i -o ./bin/docker-machine-driver-cloudca ./bin

install: build
	cp ./bin/docker-machine-driver-cloudca $(GOPATH)/bin/

build-all:
	# compile for all OS/Arch using Gox
	gox -verbose \
		-ldflags "-X main.version=${VERSION}" \
		-os="linux darwin windows freebsd openbsd solaris" \
		-arch="386 amd64 arm" \
		-osarch="!darwin/arm !darwin/386" \
		-output="dist/{{.OS}}-{{.Arch}}/{{.Dir}}" .

	# zip the executables
	for PLATFORM in `find ./dist -mindepth 1 -maxdepth 1 -type d` ; do \
		OSARCH=`basename $$PLATFORM` ; \
		echo "--> $$OSARCH" ; \
		pushd $$PLATFORM >/dev/null 2>&1 ; \
		zip ../$$OSARCH.zip ./* ; \
		popd >/dev/null 2>&1 ; \
	done

clean:
	rm -rf dist bin/docker-machine-driver-cloudca

.PHONY: init build install build-all clean
