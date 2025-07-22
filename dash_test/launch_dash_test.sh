#!/bin/bash

# Display usage message
display_usage() {
    echo "Usage: $0 <sleep_time> <num_tests>"
    echo "Example: $0 500 2"
}

# Check for correct number of arguments
if [ "$#" -ne 2 ]; then
    display_usage
    exit 1
fi

SLEEP_TIME=$1
NUM_TEST=$2

for ((i=1; i<=NUM_TEST; i++)); do
    echo "========== Test $i of $NUM_TEST =========="

    # Kill leftover Firefox processes before starting
    pkill -f firefox
    sleep 1

    echo "Sleeping 5 seconds before starting Firefox..."
    sleep 5

    # Launch Firefox
    firefox /home/maryam/FreeBSD/dash_test/index.html &
    FIREFOX_PID=$!
    echo "Firefox started with PID $FIREFOX_PID"

    sleep "${SLEEP_TIME}"

    echo "Time is up. Closing Firefox..."
    pkill -f firefox

    echo "Test $i completed."
    echo "------------------------------------------"
done

echo "✅ All $NUM_TEST test(s) completed."
