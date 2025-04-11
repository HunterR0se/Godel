#!/bin/bash

# Build and run script for Godel

# Build the application
echo "Building Godel..."
go build -o godel main.go

if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

echo "Build successful!"
sleep 1
./godel

echo "Press any key to continue..."
read -n 1 -s

./godel -dir test_samples

#echo "Press any key to do Webcrawl"
#read -n 1 -s
#./godel -dir Webcrawl