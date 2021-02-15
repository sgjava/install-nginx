#!/bin/sh
#
# Created on August 13, 2020
#
# @author: sgoldsmith
#
# Configure nginx for SSL on Ubuntu 20.04. This may work on other versions and Debian like distributions.
#
# Change variables below to suit your needs. Requires install.sh to be run first.
#
# Steven P. Goldsmith
# sgjava@gmail.com
#

# Change to your domain before running
domain="yourdomain.com"

# List of domains for acme.sh (remove --staging for production certificate)
domainlist="--staging -d yourdomain.com -d www.yourdomain.com -d mail.yourdomain.com"

# ct-submit URL
acmeshurl="https://github.com/Neilpang/acme.sh.git"

# Get architecture
arch=$(uname -m)

# Get FQDN
hostname=$(hostname -f)

# Temp dir for downloads, etc.
tmpdir="$HOME/temp"

# Cron related
croncmd="$HOME/update-certs.sh >> $HOME/update-certs.log 2>&1"
cronjob="8 0 * * * $croncmd"

# stdout and stderr for commands logged
logfile="$PWD/ssl.log"
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

# Update update-certs.sh
log "Update update-certs.sh..."
cp update-certs.sh "$HOME" >> $logfile 2>&1
sed -i "s|domain=|domain=\""$domain"\"|g" "$HOME/update-certs.sh" >> $logfile 2>&1
sed -i "s|home=|home=\""$HOME"\"|g" "$HOME/update-certs.sh" >> $logfile 2>&1

# Add to crontab
( sudo crontab -l | grep -v -F "$croncmd" ; echo "$cronjob" ) | sudo crontab -

log "Installing dependencies..."
sudo -E apt-get -y update >> $logfile 2>&1
sudo -E apt-get -y upgrade >> $logfile 2>&1
sudo -E apt-get -y install wget curl socat >> $logfile 2>&1

# Clone acme.sh
log "Cloning acme.sh..."
cd >> $logfile 2>&1
git clone --depth 1 "$acmeshurl" >> $logfile 2>&1
cd acme.sh >> $logfile 2>&1
log "Install acme.sh..."
./acme.sh --install >> $logfile 2>&1
. ~/.bashrc >> $logfile 2>&1
sudo -E setcap 'cap_net_bind_service=+ep' /usr/bin/socat >> $logfile 2>&1
log "Stopping nginx..."
sudo -E systemctl stop nginx.service >> $logfile 2>&1
log "Issue cert..."
# Make sure port 80 is open and DNS names resolve to this machine
./acme.sh --issue --standalone $domainlist >> $logfile 2>&1
sudo -E cp ~/.acme.sh/"$domain"/ca.cer /etc/ssl/certs >> $logfile 2>&1
sudo -E chmod 644 /etc/ssl/certs/ca.cer >> $logfile 2>&1
sudo -E cp ~/.acme.sh/"$domain"/fullchain.cer /etc/ssl/certs >> $logfile 2>&1
sudo -E chmod 644 /etc/ssl/certs/fullchain.cer >> $logfile 2>&1
sudo -E cp ~/.acme.sh/"$domain"/"$domain".key /etc/ssl/private >> $logfile 2>&1
sudo -E chmod 600 /etc/ssl/private/"$domain".key >> $logfile 2>&1

log "Generate dhparam.pem..."
sudo -E openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048 >> $logfile 2>&1

# Submit fullchain.cer for certificate transparency
log "Submitting certificate to logs..."
sudo -E mkdir -p /etc/ssl/sct >> $logfile 2>&1
sudo -E sh -c "/usr/local/src/ct-submit/ct-submit sabre.ct.comodo.com < ~/.acme.sh/codeferm.com/fullchain.cer > /etc/ssl/sct/comodo-sabre.sct" >> $logfile 2>&1
sudo -E sh -c "/usr/local/src/ct-submit/ct-submit ct.googleapis.com/logs/argon2021 < ~/.acme.sh/codeferm.com/fullchain.cer > /etc/ssl/sct/google-argon2021.sct" >> $logfile 2>&1
sudo -E sh -c "/usr/local/src/ct-submit/ct-submit ct.googleapis.com/logs/xenon2021 < ~/.acme.sh/codeferm.com/fullchain.cer > /etc/ssl/sct/google-xenon2021.sct" >> $logfile 2>&1
sudo -E sh -c "/usr/local/src/ct-submit/ct-submit ct.cloudflare.com/logs/nimbus2021 < ~/.acme.sh/codeferm.com/fullchain.cer > /etc/ssl/sct/cloudflare-nimbus2021.sct" >> $logfile 2>&1
sudo -E sh -c "/usr/local/src/ct-submit/ct-submit yeti2021.ct.digicert.com/log < ~/.acme.sh/codeferm.com/fullchain.cer > /etc/ssl/sct/digicert-yeti2021.sct" >> $logfile 2>&1

# Add SSL configuration
log "Add SSL configuration..."
sudo -E sed -i '/#gzip  on;/a \
    server {\
	listen       443 ssl http2;\
	server_name '"$hostname"';\
\
	ssl_certificate      \/etc\/ssl\/certs\/fullchain.cer;\
	ssl_certificate_key  \/etc\/ssl\/private\/'"$domain.key"';\
	ssl_trusted_certificate \/etc\/ssl\/certs\/ca.cer;\
\
	ssl_ct on;\
	ssl_ct_static_scts /etc/ssl/sct;\
\
	ssl_session_cache shared:le_nginx_SSL:1m;\
	ssl_session_timeout 1d;\
	ssl_session_tickets off;\
\
	ssl_protocols TLSv1.2 TLSv1.3;\
	ssl_prefer_server_ciphers on;\
	ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";\
	ssl_ecdh_curve secp384r1;\
\
	ssl_stapling on;\
	ssl_stapling_verify on;\
	resolver 8.8.8.8 8.8.4.4 valid=300s;\
	resolver_timeout 5s;\
\
	add_header Strict-Transport-Security "max-age=15768000; includeSubdomains; preload;";\
	add_header Content-Security-Policy "default-src \x27none\x27; frame-ancestors \x27none\x27; script-src \x27self\x27; img-src \x27self\x27; style-src \x27self\x27; base-uri \x27self\x27; form-action \x27self\x27";\
	add_header Referrer-Policy "no-referrer, strict-origin-when-cross-origin";\
	add_header X-Frame-Options SAMEORIGIN;\
	add_header X-Content-Type-Options nosniff;\
	add_header X-XSS-Protection "1; mode=block";\
\
        location \/ {\
            if ($allowed_country = no) {\
                return 403;\
            }\
            root   html;\
            index  index.html index.htm;\
        }\
    }' /etc/nginx/nginx.conf >> $logfile 2>&1

log "Starting nginx..."
sudo -E systemctl start nginx.service >> $logfile 2>&1

log "Removing temp dir $tmpdir"
rm -rf "$tmpdir" >> $logfile 2>&1
