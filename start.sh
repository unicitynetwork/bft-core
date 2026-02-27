#!/bin/bash

# exit on error
set -e

source helper.sh

usage() {
  echo "Usage: $0 [-h usage] [-r start root]"
  exit 0
}

# start requires an argument
[ $# -eq 0 ] && usage

# handle arguments
while getopts "hr" o; do
  case "${o}" in
  r)
    echo -n "starting root nodes..." && start_root_nodes
    ;;
  h | *) # help.
    usage
    ;;
  esac
done
