#!/bin/bash

PGUSER="scrolladmin"
PGPASSWORD="123456"
PGHOST="localhost"

DBNAME=(
 "postgres://blockscout:.pvtx4ii3axa@172.22.0.1:5432/scroll_blockscout?sslmode=require"
 "postgres://bridge_history:.f6j222eplao@172.22.0.1:5432/scroll_bridge_history?sslmode=require"
 "postgres://chain_monitor:.ezweykn1mxk@172.22.0.1:5432/scroll_chain_monitor?sslmode=require"
 "postgres://rollup_node:0.wi127xys22@172.22.0.1:5432/scroll_rollup?sslmode=require"
 "postgres://rollup_node:0.wi127xys22@172.22.0.1:5432/scroll_rollup?sslmode=require"
 "postgres://l1_explorer:0.jdt0o8r51c@172.22.0.1:5432/scroll_l1explorer?sslmode=require"
 "postgres://rollup_node:0.wi127xys22@172.22.0.1:5432/scroll_rollup?sslmode=require"
 "postgres://rollup_node:0.wi127xys22@172.22.0.1:5432/scroll_rollup?sslmode=require"
 "postgres://rollup_node:0.wi127xys22@172.22.0.1:5432/scroll_rollup?sslmode=require"
 "postgres://rollup_node:0.wi127xys22@172.22.0.1:5432/scroll_rollup?sslmode=require"
)
export PGPASSWORD

# Process each database connection string
for db_url in "${DBNAME[@]}"; do
    echo "--------------------------------------------------"
    echo "Processing URL: $db_url"

    # Extract database name
    # Example: postgres://user:pass@host:port/dbname?query
    # Remove protocol part: user:pass@host:port/dbname?query
    path_part_for_dbname="${db_url#*://}"
    # Remove user:pass@host:port part: dbname?query
    dbname_with_query="${path_part_for_dbname#*/}"
    # Remove query string: dbname
    actual_db_name="${dbname_with_query%%\?*}"

    # Extract original owner (username)
    # Remove protocol part: user:pass@host:port/dbname?query
    user_info_part="${db_url#*://}"
    # Remove @host... part: user:pass
    user_pass_part="${user_info_part%%@*}"
    # Remove :password... part: user
    original_owner="${user_pass_part%%:*}"

    echo "actual_db_name= ${actual_db_name} original_owner=${original_owner}"
    
    #continue

    if [ -z "$actual_db_name" ] || [ -z "$original_owner" ]; then
        echo "Error: Could not parse database name or owner from URL: $db_url"
        echo "Skipping this entry."
        echo "--------------------------------------------------"
        continue
    fi

    echo "  Database Name: $actual_db_name"
    echo "  Original Owner: $original_owner"

    # Terminate existing connections to the database
    echo "  Terminating connections to database '$actual_db_name'..."
    psql -U "$PGUSER" -h "$PGHOST" -d postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='$actual_db_name' AND pid <> pg_backend_pid();"

    # Drop the database if it exists
    echo "  Dropping database '$actual_db_name' (if exists)..."
    psql -U "$PGUSER" -h "$PGHOST" -d postgres -c "DROP DATABASE IF EXISTS \"$actual_db_name\";"

    # Create the database with the original owner
    echo "  Creating database '$actual_db_name' with owner '$original_owner'..."
    psql -U "$PGUSER" -h "$PGHOST" -d postgres -c "CREATE DATABASE \"$actual_db_name\" OWNER \"$original_owner\";"
    
    if [ $? -ne 0 ]; then
        echo "Error: Failed to create database '$actual_db_name' with owner '$original_owner'."
    else
        echo "Successfully recreated database '$actual_db_name' with owner '$original_owner'."
    fi
    echo "--------------------------------------------------"
done

unset PGPASSWORD

echo "All specified databases processed."
