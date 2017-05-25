#!/bin/bash

VERSION="$(git describe --tags)"
function getUrl() {
    echo $(cat ./dist/docker-machine-driver-cloudca_${VERSION}_SWIFTURLS | grep $1)
}

echo "[DESCRIPTION HERE]

# Issues fixed
[ISSUES HERE]

# Downloads

**macOS**
- 64-bit: $(getUrl darwin)

**Linux**
- 64-bit:  $(getUrl linux-amd64)
- 32-bit: $(getUrl linux-386)
- Arm: $(getUrl linux-arm)

**Windows**
- 64-bit: $(getUrl windows-amd64)
- 32-bit: $(getUrl windows-386)
"