#!/bin/bash
root_nodes=3
reset_db_only=false
# exit on error
set -e

# print help
usage() {
  echo "Generate 'test-nodes' structure, log configuration and genesis files. Usage: $0 [-h usage] [-r number of root nodes] [-c reset all DB files]"
  exit 0
}
# handle arguments
while getopts "chr:" o; do
  case "${o}" in
  c)
    reset_db_only=true
    ;;
  r)
    root_nodes=${OPTARG}
    ;;
  h | *) # help.
    usage
    ;;
  esac
done

if [ "$reset_db_only" == true ]; then
  echo "deleting all *.db files"
  find test-nodes/*/* -name *.db -type f -delete
  exit 0
fi

# make clean will remove "test-nodes" directory with all of the content
echo "clearing 'test-nodes' directory and building Unicity"
make clean build
mkdir test-nodes

# get common functions
source helper.sh

init_root_nodes $root_nodes

# generate log configuration for all nodes
generate_log_configuration "test-nodes/*/"
