#!/bin/sh
#
# Created on September 7, 2020
#
# @author: sgoldsmith
#
# Update certs from "$home"/.acme.sh directory to /etc/ssl/certs andprovate key to /etc/ssl/private
#
# This script will be updated by ssl.sh.
#
# Steven P. Goldsmith
# sgjava@gmail.com
#

# Change to your domain before running (modified by ssl.sh)
domain=

# Change to acme dir (modified by ssl.sh)
home=

# true if any cert is updated
newcert=false

# Simple logger
log(){
	timestamp=$(date +"%m-%d-%Y %k:%M:%S")
	echo "$timestamp $1"
}

# Update ca.cer
if [ $(diff -q "$home"/.acme.sh/"$domain"/ca.cer /etc/ssl/certs/ca.cer) -n "" ]; then
	log "Updating ca.cer"
	cp "$home"/.acme.sh/"$domain"/ca.cer /etc/ssl/certs
	newcert=true
fi

# Update fullchain.cer
if [ $(diff -q "$home"/.acme.sh/"$domain"/fullchain.cer /etc/ssl/certs/fullchain.cer) -n "" ]; then
	log log "Updating fullchain.cer"
	cp "$home"/.acme.sh/"$domain"/fullchain.cer /etc/ssl/certs
	sh -c "/usr/local/src/ct-submit/ct-submit sabre.ct.comodo.com < "$home"/.acme.sh/codeferm.com/fullchain.cer > /etc/ssl/sct/comodo-sabre.sct"
	sh -c "/usr/local/src/ct-submit/ct-submit ct.googleapis.com/logs/argon2021 < "$home"/.acme.sh/codeferm.com/fullchain.cer > /etc/ssl/sct/google-argon2021.sct"
	sh -c "/usr/local/src/ct-submit/ct-submit ct.googleapis.com/logs/xenon2021 < "$home"/.acme.sh/codeferm.com/fullchain.cer > /etc/ssl/sct/google-xenon2021.sct"
	sh -c "/usr/local/src/ct-submit/ct-submit ct.cloudflare.com/logs/nimbus2021 < "$home"/.acme.sh/codeferm.com/fullchain.cer > /etc/ssl/sct/cloudflare-nimbus2021.sct"
	sh -c "/usr/local/src/ct-submit/ct-submit yeti2021.ct.digicert.com/log < "$home"/.acme.sh/codeferm.com/fullchain.cer > /etc/ssl/sct/digicert-yeti2021.sct"
	newcert=true	
fi

# Update private key
if [ $(diff -q "$home"/.acme.sh/"$domain"/"$domain".key /etc/ssl/private/"$domain".key) -n "" ]; then
	log log "Updating $domain.key"
	cp "$home"/.acme.sh/"$domain"/"$domain".key /etc/ssl/private
	newcert=true
fi

# If any cert changed stop/start nginx service
if [ "$newcert" = true ] ; then
	log "Stopping nginx..."
 	systemctl stop nginx.service
	log "Starting nginx..."
 	systemctl start nginx.service
else
	log "No certificate updates"
fi
