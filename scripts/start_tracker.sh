#!/bin/bash

_script=$(readlink -f ${BASH_SOURCE[0]})
BASE_DIR="$(dirname $_script)/../.."

PORT=$1
RESTART=$(echo "$2" | tr '[:upper:]' '[:lower:]')

STATE_DIR="$BASE_DIR/dispersy-$PORT"
TWISTD_PID_FILE="$STATE_DIR/twisted.pid"

# set PYTHONPATH
PYTHONPATH="$BASE_DIR/dispersy:$PYTHONPATH"
export PYTHONPATH

# check port number
if [ -z "$PORT" -a "$PORT" != " " ]; then
    echo "Port number unspecified"
    echo "Usage: <script> <port> [restart]"
    echo "  <port>:    The port number to use"
    echo "  [restart]: use 'true' to restart the tracker if a running one if found"
    exit 1
fi

# check and create state_dir
if [ ! -d "$STATE_DIR" ]; then
    echo "Creating state_dir $STATE_DIR"
    mkdir $STATE_DIR
fi

# check if twistd.pid is present and if a process is already running
if [ -e "$TWISTD_PID_FILE" ]; then
    echo "Checking twistd.pid"
    pid=$(head -1 "$TWISTD_PID_FILE")

    for p in $(ps aux | awk '{print $2}' | tail -n +2)
    do
        if [ "$p" == "$pid" ]; then
            if [ "$RESTART" == "true" ]; then
                echo "Found a running tracker using port $PORT, restarting"
                kill $pid
                sleep 2
            else
                echo "Found a running tracker using port $PORT, exiting"
                exit 1
            fi
        fi
    done
fi


# start tracker
echo "Starting tracker using port $PORT..."
twistd --pidfile=$TWISTD_PID_FILE tracker --port=$PORT --statedir=$STATE_DIR

sleep 2

if [ ! -e "$TWISTD_PID_FILE" ]; then
    echo "Tracker failed to start"
    exit 3
fi

echo "done"
exit 0