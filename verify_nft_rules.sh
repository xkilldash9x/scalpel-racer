#!/bin/bash
# verify_nft_rules.sh
# Verifies that the 'scalpel_racer_ctx' table and rules are correctly applied.

TABLE_NAME="scalpel_racer_ctx"

if ! command -v nft &> /dev/null; then
    echo "Error: 'nft' command not found."
    exit 1
fi

echo "Checking for nftables table: $TABLE_NAME..."

if nft list tables | grep -q "$TABLE_NAME"; then
    echo " [OK] Table '$TABLE_NAME' exists."
    echo "---------------------------------------------------"
    nft list table inet "$TABLE_NAME"
    echo "---------------------------------------------------"
    if nft list table inet "$TABLE_NAME" | grep -q "queue num 99"; then
        echo " [OK] Rule directs traffic to NFQUEUE num 99."
    else
        echo " [FAIL] Rule NOT found or has incorrect queue number."
    fi
else
    echo " [FAIL] Table '$TABLE_NAME' does not exist."
    echo "        Is the packet_controller.py running?"
fi
