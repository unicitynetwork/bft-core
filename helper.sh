#!/bin/bash

rootPortStart=26662

# generate logger configuration file
function generate_log_configuration() {
  # to iterate over all home directories
  for homedir in $1; do
    # generate log file itself
    cat <<EOT >> "$homedir/logger-config.yaml"
# File name to log to. If not set, logs to stdout.
outputPath:
# Controls if goroutine ID is added to log.
showGoroutineID: true
# The default log level for all loggers
# Possible levels: NONE; ERROR; WARNING; INFO; DEBUG; TRACE
defaultLevel: DEBUG
# Output format for log records (text: "parser friendly" plain text;)
format: text
# Sets time format to use for log record timestamp. Uses Go time
# format, ie "2006-01-02T15:04:05.0000Z0700" for more see
# https://pkg.go.dev/time#pkg-constants
# special value "none" can be used to disable logging timestamp;
timeFormat: "2006-01-02T15:04:05.0000Z0700"
# How to format peer ID values (ie node id):
# - none: do not log peer id at all;
# - short: log shortened id (middle part replaced with single *);
# otherwise full peer id is logged.
# This setting is not respected by ECS handler which always logs full ID.
peerIdFormat: short
EOT
  done
  return 0
}

# generate bootstrap parameter from key file and port
function boot_node() {
  local home=$1
  local rootPort=$2
  nodeId=$(build/ubft node-id --home $home | tail -n1)
  echo "/ip4/127.0.0.1/tcp/$rootPort/p2p/$nodeId"
}

# Initiallize root nodes
# $1 number of root nodes
function init_root_nodes() {
  home=test-nodes/root
  nodeInfoFiles=
  echo "initializing $1 nodes for root chain"
  for i in $(seq 1 "$1")
  do
    build/ubft root-node init --home "${home}$i" -g
    nodeInfoFiles+=" --node-info ${home}$i/node-info.json"
  done

  # Generate trust-base once to test-nodes
  build/ubft trust-base generate --home test-nodes --epoch 0 --epoch-start 1 --network-id 3 $nodeInfoFiles

  # Sign trust-base by each node
  for i in $(seq 1 "$1")
  do
    build/ubft trust-base sign --home ${home}$i --trust-base test-nodes/trust-base.json
  done
}

function start_root_nodes() {
  # use root node 1 as bootstrap node
  local bootNode=""
  local p2pPort=$rootPortStart
  local rpcPort=25866

  bootNode=$(boot_node test-nodes/root1 "$rootPortStart")

  i=1
  for node in test-nodes/root*
  do
    if [[ $i -ne 1 ]]; then
      bootNodeParam="--bootnodes=$bootNode"
    fi

    build/ubft root-node run \
                    --home test-nodes/root$i \
                    --address "/ip4/127.0.0.1/tcp/$p2pPort" \
                    $bootNodeParam \
                    --trust-base test-nodes/trust-base.json \
                    --rpc-server-address "localhost:$rpcPort" \
                    --log-format text \
                    --log-level debug \
                    --metrics prometheus \
                    >> test-nodes/root$i/debug.log 2>&1 &
    nodePID=$!
    # wait until node starts listening on RPC port OR exits because of some error
    until lsof -i:$rpcPort >/dev/null || ! ps -p $nodePID >/dev/null
    do
      echo -n "."
      sleep 0.200
    done

    if ! ps -p $nodePID >/dev/null; then
      echo "failed"
      exit
    fi

    if ls test-nodes/shard-conf-* >/dev/null 2>&1; then
      # uplaod all shard confs
      for shardConf in test-nodes/shard-conf-*
      do
        curl -X PUT -H "Content-Type: application/json" -d @${shardConf} \
             http://localhost:${rpcPort}/api/v1/configurations
      done
    fi

    ((p2pPort=p2pPort+1))
    ((rpcPort=rpcPort+1))
    ((i=i+1))
  done

  echo
  echo "started $(($i-1)) root nodes"
}
