# SearxWizard
## Prerequisites
You should have a fresh install of Ubuntu Server 20.04 up and running. The script will take it from there. Make sure you have about 1 GB RAM on your server if possible or create a swapfile.
## How it works
SearxWizard will install and configure `nginx`, `acme.sh`, `docker-ce` and set up your Searx instance. It will also create the user `letsencrypt` to handle `acme.sh` certificates. You should read what exactly the script does before executing.

## Install
Clone repo to server, run the script with `bash searxwizard.sh` and follow the instructions.
