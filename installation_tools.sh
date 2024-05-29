#!/bin/bash

programs=(
	golang-go
	feroxbuster
	subfinder
	dnsx
	gobuster
	nuclei
	wpscan
	wafw00f
)

sudo apt install "${programs[@]}" -y

