#!/bin/sh
#
# Created on August 13, 2020
#
# @author: sgoldsmith
#
# Install nginx from source on Ubuntu 20.04. This may work on other versions and Debian like distributions.
#
# Change variables below to suit your needs.
#
# Steven P. Goldsmith
# sgjava@gmail.com
#

# nginx URL
nginxurl="https://nginx.org/download/nginx-1.19.6.tar.gz"

# PCRE URL
pcreurl="https://ftp.pcre.org/pub/pcre/pcre-8.44.tar.gz"

# OpenSSL URL
opensslurl="https://www.openssl.org/source/openssl-1.1.1i.tar.gz"

# Certificate Transparency module URL
cturl="https://github.com/grahamedgecombe/nginx-ct.git"

# ct-submit URL
ctsubmiturl="https://github.com/grahamedgecombe/ct-submit.git"

# geoip2 module
geoip2url="https://github.com/leev/ngx_http_geoip2_module.git"

# GeoIP account
export accountid=""

# GeoIP key
export licensekey=""

# Where to put nginx source
srcdir="/usr/local/src"

# Get FQDN
hostname=$(hostname -f)

# Get architecture
arch=$(uname -m)

# Temp dir for downloads, etc.
tmpdir="$HOME/temp"

# Cron related
croncmd1="/usr/bin/sh -c \"date '+%Y-%m-%d %H:%M:%S' >> /home/servadmin/geoipupdate.log 2>&1 && geoipupdate -v -d /etc/nginx/geoip >> /home/servadmin/geoipupdate.log 2>&1\""
cronjob1="0 0 * * * $croncmd1"
# acme.sh runs at 25 0 * * * and required nginx stopped first (see crontab -l after install)
croncmd2="/usr/bin/sh -c \"service nginx stop\""
cronjob2="24 0 * * * $croncmd2"
croncmd3="/usr/bin/sh -c \"service nginx start\""
cronjob3="28 0 * * * $croncmd3"

# stdout and stderr for commands logged
logfile="$PWD/install.log"
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

# Create geoipupdate configuration
sudo -E sh -c 'cat <<EOF >/etc/GeoIP.conf
AccountID $accountid
LicenseKey $licensekey
EditionIDs GeoLite2-Country GeoLite2-City GeoLite2-ASN
EOF'
# Install geoipupdate, but keep our configuration file
sudo -E apt -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" install geoipupdate >> $logfile 2>&1
# Create geoip dir to hold database files
sudo -E mkdir -p /etc/nginx/geoip >> $logfile 2>&1
# Download geoip database files
sudo -E geoipupdate -d /etc/nginx/geoip >> $logfile 2>&1

# Add to crontab
( sudo crontab -l | grep -v -F "$croncmd1" ; echo "$cronjob1" ) | sudo crontab -
( sudo crontab -l | grep -v -F "$croncmd2" ; echo "$cronjob2" ) | sudo crontab -
( sudo crontab -l | grep -v -F "$croncmd3" ; echo "$cronjob3" ) | sudo crontab -

# Get directory name $1 = URL
getdirname () {
	archive=$(basename "$1")
	# Remove .gz
	name="${archive%.*}"
	# Remove .tar
	echo "${name%.*}"
}

# Download source $1 = URL
download () {
    archive=$(basename "$1")
	# Download source
	log "Downloading $1 to $tmpdir"
	wget -q --directory-prefix=$tmpdir "$1" >> $logfile 2>&1
	log "Extracting $archive to $tmpdir"
	tar -xf "$tmpdir/$archive" -C "$tmpdir" >> $logfile 2>&1
	# Remove .gz
	filename="${archive%.*}"
	# Remove .tar
	filename="${filename%.*}"
	sudo -E mv "$tmpdir/$filename" "${srcdir}" >> $logfile 2>&1
}

log "Installing dependencies..."
sudo -E apt-get -y update >> $logfile 2>&1
sudo -E apt-get -y upgrade >> $logfile 2>&1
sudo -E apt-get -y install golang software-properties-common ufw build-essential git libmaxminddb0 libmaxminddb-dev mmdb-bin >> $logfile 2>&1

# Download source files and extract
download "$nginxurl"
download "$pcreurl"
download "$opensslurl"
# Clone Certificate Transparency module
log "Cloning nginx-ct module..."
sudo -E git clone --depth 1 "$cturl" "$srcdir/nginx-ct" >> $logfile 2>&1
# Clone ct-submit
log "Cloning ct-submit..."
sudo -E git clone --depth 1 "$ctsubmiturl" "$srcdir/ct-submit" >> $logfile 2>&1
# Clone geoip2 module
log "Cloning geoip2 module..."
sudo -E git clone --depth 1 "$geoip2url" "$srcdir/ngx_http_geoip2_module" >> $logfile 2>&1

# Build with minimal modules, tweak as needed
log "Building nginx..."
nginxdir=$(getdirname "$nginxurl")
cd "${srcdir}/${nginxdir}" >> $logfile 2>&1
# Patch source to remove "nginx" from headers and error pages
log "Patching source to remove "nginx" from headers and error pages"
sed -i 's@"nginx/"@"-/"@g' src/core/nginx.h
sed -i 's@r->headers_out.server == NULL@0@g' src/http/ngx_http_header_filter_module.c $logfile 2>&1
sed -i 's@r->headers_out.server == NULL@0@g' src/http/v2/ngx_http_v2_filter_module.c $logfile 2>&1
sed -i 's@<hr><center>nginx</center>@@g' src/http/ngx_http_special_response.c $logfile 2>&1
# Configure buld
sudo -E ./configure --prefix=/etc/nginx \
--sbin-path=/usr/sbin/nginx \
--modules-path=/usr/lib/nginx/modules \
--conf-path=/etc/nginx/nginx.conf \
--error-log-path=/var/log/nginx/error.log \
--pid-path=/var/run/nginx.pid \
--lock-path=/var/run/nginx.lock \
--user=nginx \
--group=nginx \
--build=Ubuntu \
--builddir=${nginxdir} \
--without-http_autoindex_module \
--without-http_gzip_module \
--without-http_fastcgi_module \
--without-http_uwsgi_module \
--without-http_scgi_module \
--without-http_grpc_module \
--with-threads \
--with-file-aio \
--with-http_ssl_module \
--with-http_v2_module \
--http-log-path=/var/log/nginx/access.log \
--http-client-body-temp-path=/var/cache/nginx/client_temp \
--http-proxy-temp-path=/var/cache/nginx/proxy_temp \
--with-pcre=../$(getdirname "$pcreurl") \
--with-pcre-jit \
--with-openssl=../$(getdirname "$opensslurl") \
--with-openssl-opt=no-nextprotoneg \
--add-dynamic-module=../nginx-ct \
--add-dynamic-module=../ngx_http_geoip2_module \
--with-debug >> $logfile 2>&1
sudo -E make -j$(getconf _NPROCESSORS_ONLN) >> $logfile 2>&1
sudo -E make install >> $logfile 2>&1

log "Create dirs..."
# Symlink /usr/lib/nginx/modules to /etc/nginx/modules directory. etc/nginx/modules is a standard place for nginx modules.
sudo -E ln -sfn /usr/lib/nginx/modules /etc/nginx/modules >> $logfile 2>&1
# Create an Nginx system group and user
sudo -E adduser --system --shell /bin/false --no-create-home --disabled-login --disabled-password --gecos "nginx user" --group nginx >> $logfile 2>&1
# Create nginx cache directories and set proper permissions
sudo -E mkdir -p /var/cache/nginx/client_temp /var/cache/nginx/proxy_temp >> $logfile 2>&1
sudo -E chmod 700 /var/cache/nginx/* >> $logfile 2>&1
sudo -E chown nginx:root /var/cache/nginx/* >> $logfile 2>&1

# Install nginx server service
log "Installing nginx service..."
sudo tee -a /etc/systemd/system/nginx.service > /dev/null <<EOT
[Unit]
Description=nginx - high performance web server
Documentation=https://nginx.org/en/docs/
After=network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/var/run/nginx.pid
ExecStartPre=/bin/sleep 5
ExecStartPre=/usr/sbin/nginx -t -c /etc/nginx/nginx.conf
ExecStart=/usr/sbin/nginx -c /etc/nginx/nginx.conf
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID

[Install]
WantedBy=multi-user.target
EOT

# Dynamically load geoip and certificate transparency modules 
sudo -E sed -i '/worker_processes/a load_module modules/ngx_http_geoip2_module.so;\
load_module modules/ngx_ssl_ct_module.so;\
load_module modules/ngx_http_ssl_ct_module.so;' /etc/nginx/nginx.conf
# Hide server and add geoip config
sudo -E sed -i '/default_type/a \
    server_tokens off;\
\
    geoip2 /etc/nginx/geoip/GeoLite2-Country.mmdb {\
        auto_reload 60m;\
        $geoip2_metadata_country_build metadata build_epoch;\
        $geoip2_data_country_code country iso_code;\
        $geoip2_data_country_name country names en;\
    }\
\
    geoip2 /etc/nginx/geoip/GeoLite2-City.mmdb {\
        auto_reload 60m;\
        $geoip2_metadata_city_build metadata build_epoch;\
        $geoip2_data_city_name city names en;\
        $geoip2_data_state_code subdivisions 0 iso_code;\
    }\
\
    map $geoip2_data_country_code $allowed_country {\
        default no;\
        CA yes;\
        US yes;\
    }\
\
    log_format main\
        \x27$remote_addr - $remote_user [$time_local] \"$request\" \x27\
        \x27$status $body_bytes_sent \"$http_referer\" \x27\
        \x27\"$http_user_agent\" \"$http_x_forwarded_for\" \x27\
        \x27$geoip2_data_city_name, $geoip2_data_state_code, $geoip2_data_country_code\x27;\
\
    access_log \/var\/log\/nginx\/access.log main;' /etc/nginx/nginx.conf >> $logfile 2>&1
# Return 403 for blocked countries
sudo -E awk '{print} /location/ && !n {print "            if ($allowed_country = no) {\n                return 403;\n            }"; n++}' /etc/nginx/nginx.conf > tmp
sudo -E cp -p tmp /etc/nginx/nginx.conf >> $logfile 2>&1
sudo -E rm tmp >> $logfile 2>&1
# Replace localhost with FQDN
sudo -E sed -i "s/localhost/$hostname/g" /etc/nginx/nginx.conf >> $logfile 2>&1

# Enable and start service
sudo -E systemctl enable nginx.service >> $logfile 2>&1
sudo -E systemctl start nginx.service >> $logfile 2>&1

# Create an Uncomplicated Firewall (UFW) Nginx application profile
log "Creating nginx UWF profile..."
sudo tee -a /etc/ufw/applications.d/nginx > /dev/null <<EOT
[Nginx HTTP]
title=Web Server (Nginx, HTTP)
description=Small, but very powerful and efficient web server
ports=80/tcp

[Nginx HTTPS]
title=Web Server (Nginx, HTTPS)
description=Small, but very powerful and efficient web server
ports=443/tcp

[Nginx Full]
title=Web Server (Nginx, HTTP + HTTPS)
description=Small, but very powerful and efficient web server
ports=80,443/tcp
EOT

# Allow ssh
sudo -E ufw allow 'OpenSSH' >> $logfile 2>&1
# Allow nginx
sudo -E ufw allow 'Nginx Full' >> $logfile 2>&1

log "Create dir structure..."
# Remove .default files from /etc/nginx directory
sudo -E rm /etc/nginx/*.default >> $logfile 2>&1
# Create basic directory structure that is most commonly used
sudo -E mkdir -p /etc/nginx/conf.d /etc/nginx/snippets /etc/nginx/sites-available /etc/nginx/sites-enabled >> $logfile 2>&1
# Set log permissions
sudo -E chmod 640 /var/log/nginx/* >> $logfile 2>&1
sudo -E chown nginx:adm /var/log/nginx/access.log /var/log/nginx/error.log >> $logfile 2>&1

# Create a log rotation config
log "Creating log rotation config..."
sudo tee -a /etc/logrotate.d/nginx > /dev/null <<EOT
/var/log/nginx/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 640 nginx adm
    sharedscripts
    postrotate
        nginx -s reload
    endscript
}
EOT

# Build ct-submit
log "Building ct-submit..."
cd "$srcdir/ct-submit"
sudo -E go build
log "Removing temp dir $tmpdir"
rm -rf "$tmpdir" >> $logfile 2>&1
