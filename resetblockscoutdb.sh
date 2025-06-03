#!/bin/bash

PGUSER="scrolladmin"
PGPASSWORD="123456"
PGHOST="192.168.1.12" # 全局目标主机
port=5434             # 全局目标端口
DBNAME=(
 "postgres://blockscout:.pvtx4ii3axa@127.0.0.1:5434/scroll_blockscout?sslmode=require"
 "postgres://bridge_history:.f6j222eplao@127.0.0.1:5434/scroll_bridge_history?sslmode=require"
 "postgres://chain_monitor:.ezweykn1mxk@127.0.0.1:5434/scroll_chain_monitor?sslmode=require"
 "postgres://l1_explorer:0.jdt0o8r51c@127.0.0.1:5434/scroll_l1explorer?sslmode=require"
 "postgres://rollup_node:0.wi127xys22@127.0.0.1:5434/scroll_rollup?sslmode=require"
)
export PGPASSWORD

# Process each database connection string
for db_url in "${DBNAME[@]}"; do
    echo "--------------------------------------------------"
    echo "Processing URL for metadata: $db_url" # Clarify URL is for metadata

    # Extract database name from URL
    path_part_for_dbname="${db_url#*://}"
    dbname_with_query="${path_part_for_dbname#*/}"
    actual_db_name="${dbname_with_query%%\?*}"

    # Extract original owner (username) from URL
    user_info_part="${db_url#*://}"
    user_pass_part="${user_info_part%%@*}"
    original_owner="${user_pass_part%%:*}"

    echo "Extracted actual_db_name=${actual_db_name}, original_owner=${original_owner}"
    echo "Operations will target HOST=${PGHOST}, PORT=${port}"
    
    if [ -z "$actual_db_name" ] || [ -z "$original_owner" ]; then
        echo "Error: Could not parse database name or owner from URL: $db_url"
        echo "Skipping this entry."
        echo "--------------------------------------------------"
        continue
    fi

    echo "  Database Name (from URL): $actual_db_name"
    echo "  Original Owner (from URL): $original_owner"

    # Terminate existing connections to the database ON THE GLOBAL HOST AND PORT
    echo "  Terminating connections to database '$actual_db_name' on $PGHOST:$port..."
    psql -U "$PGUSER" -h "$PGHOST" -p "$port" -d postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='$actual_db_name' AND pid <> pg_backend_pid();"
    if [ $? -ne 0 ]; then
        echo "Warning: Failed to terminate connections to database '$actual_db_name'. This might cause the DROP to fail. Check if user $PGUSER has rights or if database exists on $PGHOST:$port."
    fi

    # Drop the database if it exists ON THE GLOBAL HOST AND PORT
    echo "  Dropping database '$actual_db_name' (if exists) on $PGHOST:$port..."
    psql -U "$PGUSER" -h "$PGHOST" -p "$port" -d postgres -c "DROP DATABASE IF EXISTS \"$actual_db_name\";"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to drop database '$actual_db_name' on $PGHOST:$port. Check permissions for $PGUSER and active connections."
        # continue # Optionally skip to next db if drop fails
    fi

    # Create the database with the original owner ON THE GLOBAL HOST AND PORT
    echo "  Creating database '$actual_db_name' with owner '$original_owner' on $PGHOST:$port..."
    psql -U "$PGUSER" -h "$PGHOST" -p "$port" -d postgres -c "CREATE DATABASE \"$actual_db_name\" OWNER \"$original_owner\";"
    
    if [ $? -ne 0 ]; then
        echo "Error: Failed to create database '$actual_db_name' with owner '$original_owner' on $PGHOST:$port. Ensure $PGUSER can create databases and set $original_owner as owner."
    else
        echo "Successfully recreated database '$actual_db_name' with owner '$original_owner' on $PGHOST:$port."
    fi
    echo "--------------------------------------------------"
done

unset PGPASSWORD

echo "All specified databases processed on $PGHOST:$port."