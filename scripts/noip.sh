#!/bin/sh
#
# Created on February 15, 2020
#
# @author: sgoldsmith
#
# Install No-IP Dynamic Update Client (DUC) on Ubuntu 20.04. This may work on other versions and Debian like distributions.
#
# Change variables below to suit your needs.
#
# Steven P. Goldsmith
# sgjava@gmail.com
#

# DUC URL
ducurl="http://www.noip.com/client/linux/noip-duc-linux.tar.gz"

# Where to put nginx source
srcdir="/usr/local/src"

# Temp dir for downloads, etc.
tmpdir="$HOME/temp"

# stdout and stderr for commands logged
logfile="$PWD/noip.log"
rm -f $logfile

# Simple logger
log(){
	timestamp=$(date +"%m-%d-%Y %k:%M:%S")
	echo "$timestamp $1"
	echo "$timestamp $1" >> $logfile 2>&1
}

log "Removing temp dir $tmpdir"
rm -rf "$tmpdir" >> $logfile 2>&1
mkdir -p "$tmpdir" >> $logfile 2>&1

archive=$(basename "$ducurl")
log "Downloading $ducurl to $tmpdir"
wget -q --directory-prefix=$tmpdir "$ducurl" >> $logfile 2>&1
log "Extracting $archive to $tmpdir"
sudo -E tar -xf "$tmpdir/$archive" -C "$srcdir" >> $logfile 2>&1
cd "$srcdir"/noip* >> $logfile 2>&1
log "Installing DUC client..."
sudo -E make install

# Install noip2 server service
log "Installing noip2 service..."
sudo tee -a /etc/systemd/system/noip2.service > /dev/null <<EOT
[Unit]
Description=noip2 service

[Service]
Type=forking
ExecStartPre=/bin/sleep 5
ExecStart=/usr/local/bin/noip2
Restart=always

[Install]
WantedBy=default.target
EOT

sudo -E systemctl enable noip2 >> $logfile 2>&1
sudo -E systemctl start noip2 >> $logfile 2>&1

log "Removing temp dir $tmpdir"
rm -rf "$tmpdir" >> $logfile 2>&1

