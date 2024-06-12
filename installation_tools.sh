#!/bin/bash

programs=(
	golang-go
	subfinder
	dnsx
	gobuster
	nuclei
	wpscan
	wafw00f
)

sudo apt install "${programs[@]}" -y

mkdir -p results/temp/