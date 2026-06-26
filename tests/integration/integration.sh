#!/bin/bash

echo "Hello Linux Users"
echo "The integration-test will start under 5 seconds ..."
echo "Build the tool ..."
go build
sleep 5

for f in ./templates/*.html; do
    echo "[INPUT] file = $f"
    ./zspure file --file "$f" --json
    echo
done

for f in ./templates/zgrab2/*.json; do
    echo "[INPUT] file = $f"
    ./zspure file --file "$f" --zgrab-input --json
    echo
done

echo "Done"