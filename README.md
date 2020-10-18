![Title](images/title.png)

Install nginx is a set of scripts to install nginx 1.9.x from source on Ubuntu
20.04 and probably other Debian derived distributions. This idea is to compile
with minimal modules and make it as secure as possible. Always check security
best practices and tweak install script and configuration as needed. I make no
claims as to the security worthiness of the configurations or compiled code.
The scripts allow:
* Compile PCRE
* Compile OpenSSL
* Compile Certificate Transparency module
* Compile ct-submit
* Compile Geoip2 module
* Patch source to remove "nginx" from headers and error pages
* Set server_tokens off
* Install acme.sh
* Generate Let's Encrypt free SSL/TLS certificate
* Submit certificate to logs
* Create systemd service
* Install cron to update any certificate changes
* Install cron to update GeoIP databases automatically
* Scores A+ on [SSL Server Test](https://www.ssllabs.com/ssltest)

## Download project
* `cd ~/`
* `git clone --depth 1 https://github.com/sgjava/install-nginx.git`

## Install script
This assumes a fresh OS install. You should try the scripts out on a VM to play
with configuration prior to doing final install.
* Register for [geolite2](https://dev.maxmind.com/geoip/geoip2/geolite2) and note account ID and license key. 
* Set /etc/hostname and /etc/hosts
* `cd ~/install-nginx/scripts`
* `nano install.sh`
* Change configuration values as needed (accountid and licensekey required)
* `./install.sh`
* Check log file for errors

## Configure SSL using Let's Encrypt certificate
Requires that install.sh has been run.
* `cd ~/install-nginx/scripts`
* `nano ssl.sh`
* Change domain to your domain
* Change domainlist to list of domain parameters for acme.sh and remove `--staging` for production certificate
* `./ssl.sh`
* Check log file for errors
* Redirect http to https by adding `return 301 https://$host$request_uri;` to http server section
* Set your DNS CAA records to `letsencrypt.org`
* Set permission on html root `sudo chmod -R 755 /etc/nginx/html/.`