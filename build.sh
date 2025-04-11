#!/bin/bash

# Build and run script for Godel

# Ensure bin directory exists
mkdir -p bin

# Build the application
echo "Building Godel..."
go build -o bin/godel main.go

if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

echo "Build successful!"
sleep 1
bin/godel

echo "Press any key to continue..."
read -n 1 -s

bin/godel -dir test_samples

#echo "Press any key to do Webcrawl"
#read -n 1 -s
#bin/godel -dir Webcrawl
