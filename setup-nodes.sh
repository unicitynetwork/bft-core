#!/bin/bash
money_nodes=3
token_nodes=3
orchestration_nodes=3
root_nodes=3
enterprise_token_nodes=0
reset_db_only=false
admin_owner_predicate=830041025820f34a250bf4f2d3a432a43381cecc4ab071224d9ceccb6277b5779b937f59055f
# exit on error
set -e

# print help
usage() {
  echo "Generate 'test-nodes' structure, log configuration and genesis files. Usage: $0 [-h usage] [-m number of money nodes] [-t number of token nodes] [-o number of orchestration nodes] [-r number of root nodes] [-c reset all DB files] [-i initial bill owner predicate] [-k number of enterprise token partition nodes] [-a enterprise token partition admin owner predicate]"
  exit 0
}
# handle arguments
while getopts "chm:t:r:e:o:i:k:a:" o; do
  case "${o}" in
  c)
    reset_db_only=true
    ;;
  m)
    money_nodes=${OPTARG}
    ;;
  t)
    token_nodes=${OPTARG}
    ;;
  r)
    root_nodes=${OPTARG}
    ;;
  o)
    orchestration_nodes=${OPTARG}
    ;;
  i)
    initial_bill_owner_predicate=${OPTARG}
    ;;
  k)
    enterprise_token_nodes=${OPTARG}
    ;;
  a)
    admin_owner_predicate=${OPTARG}
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

if [ "$money_nodes" -ne 0 ]; then
  init_shard_nodes test-nodes/money 1 1 "$money_nodes"

  if [ ! -z "${initial_bill_owner_predicate}" ]; then
    if ! sed -i 's@"initialBillOwnerPredicate": ".*"@"initialBillOwnerPredicate": "'$initial_bill_owner_predicate'"@g' test-nodes/shard-conf-1_0.json; then
      echo "Failed to set initial bill owner predicate"
    fi
  fi

  generate_shard_genesis_state test-nodes/money 1 "$money_nodes"
fi

if [ "$token_nodes" -ne 0 ]; then
  init_shard_nodes test-nodes/tokens 2 2 "$token_nodes"
  generate_shard_genesis_state test-nodes/tokens 2 "$token_nodes"
fi

if [ "$orchestration_nodes" -ne 0 ]; then
  init_shard_nodes test-nodes/orchestration 4 4 "$orchestration_nodes"
  generate_shard_genesis_state test-nodes/orchestration 4 "$orchestration_nodes"
fi

if [ "$enterprise_token_nodes" -ne 0 ]; then
  init_shard_nodes test-nodes/tokens-enterprise 2 5 "$enterprise_token_nodes"

  if [ ! -z "${admin_owner_predicate}" ]; then
    if ! sed -i 's@"adminOwnerPredicate": ".*"@"adminOwnerPredicate": "'$admin_owner_predicate'"@g' test-nodes/shard-conf-5_0.json; then
      echo "Failed to set admin owner predicate"
    fi
  fi

  generate_shard_genesis_state test-nodes/tokens-enterprise 5 "$enterprise_token_nodes"
fi

init_root_nodes $root_nodes

# generate log configuration for all nodes
generate_log_configuration "test-nodes/*/"
