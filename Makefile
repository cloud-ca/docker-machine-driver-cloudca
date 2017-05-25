
VERSION := $(shell git describe --tags)
VERSION_COMMIT := $(shell git describe --always --long)
ifeq ($(VERSION),)
VERSION:=$(VERSION_COMMIT)
endif

default: build

init:
	curl https://glide.sh/get | sh
	glide install

build: clean
	GOGC=off go build -i -o ./bin/docker-machine-driver-cloudca ./bin

install: build
	cp ./bin/docker-machine-driver-cloudca $(GOPATH)/bin/

build-all: clean
	@gox -verbose \
		-ldflags "-X main.version=$(VERSION)" \
		-os="linux darwin windows" \
		-arch="386 amd64 arm" \
		-osarch="!darwin/arm !darwin/386" \
		-output="dist/{{.OS}}-{{.Arch}}/docker-machine-driver-cloudca" ./bin

	@for PLATFORM in `find ./dist -mindepth 1 -maxdepth 1 -type d` ; do \
		OSARCH=`basename $$PLATFORM` ; \
		echo "--> $$OSARCH" ; \
		pushd $$PLATFORM >/dev/null 2>&1 ; \
		zip ../docker-machine-driver-cloudca_$(VERSION)_$$OSARCH.zip ./* ; \
		popd >/dev/null 2>&1 ; \
	done

clean:
	rm -rf dist bin/docker-machine-driver-cloudca
upload:
	rm -f ./dist/docker-machine-driver-cloudca_${VERSION}_SWIFTURLS ;
	SWIFT_ACCOUNT=`swift stat | grep Account: | sed s/Account:// | tr -d '[:space:]'` ; \
	SWIFT_URL=https://objects-qc.cloud.ca/v1 ; \
	SWIFT_CONTAINER=docker-machine-driver-cloudca ; \
	for FILE in `ls ./dist | grep -i docker-machine.*\.zip` ; do \
		echo "Uploading $$FILE to swift" ; \
		swift upload $${SWIFT_CONTAINER} ./dist/$$FILE --object-name ${VERSION}/$$FILE ; \
		echo "$${SWIFT_URL}/$${SWIFT_ACCOUNT}/$${SWIFT_CONTAINER}/${VERSION}/$$FILE" >> ./dist/docker-machine-driver-cloudca_${VERSION}_SWIFTURLS ; \
	done
release-notes: 
	./release-notes.sh > ./dist/release.md ;
release: build-all upload release-notes
.PHONY: init build install build-all clean
