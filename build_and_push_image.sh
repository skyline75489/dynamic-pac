#!/bin/sh
podman build . -t localhost:5000/skyline/dynamic-pac:latest
podman push localhost:5000/skyline/dynamic-pac:latest --tls-verify=false

