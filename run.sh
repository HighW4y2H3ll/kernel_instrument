#!/bin/bash

docker run --rm -it -v $(realpath $(dirname "${BASH_SOURCE[0]}")):/workdir -u $(id -u ${USER}):$(id -g ${USER}) cross_arm_hu "$@"
