#!/bin/bash

find_free_port() {
  local start_port=20000
  local end_port=30000

  for ((port=start_port; port<=end_port; port++)); do
    if ! ss -lnt | awk '{print $4}' | grep -q ":$port$"; then
      echo "$port"
      return 0
    fi
  done

  echo "No free port found in range $start_port-$end_port" >&2
  return 1
}

free_port=$(find_free_port)
echo "Found free port: $free_port"
