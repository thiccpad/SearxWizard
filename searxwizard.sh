 #!/bin/bash
 cat << "EOF"
+-----------------------------------+
|     ___ ___   _   ___ __  __      |
|    / __| __| /_\ | _ \\ \/ /      |
|    \__ \ _| / _ \|   / >  <       |
| __ |___/___/_/_\_\_|_\/_/\_\___   |
| \ \    / /_ _|_  / /_\ | _ \   \  |
|  \ \/\/ / | | / / / _ \|   / |) | |
|   \_/\_/ |___/___/_/_\_\_|_\___/  |
|          __ __/  \ / |            |
|          \ V / () || |            |
|           \_/ \__(_)_|            |
+-----------------------------------+                       
EOF
echo "This script will setup a fully running Searx Instance on your server for your given domain on Ubuntu 20.04."
echo "It will install Nginx, Docker and acme.sh (to configure SSL for your domain). Please use this on a fresh server install."
echo "You need to run Searx Wizard as root. Please check what exactly the script does before you run it!"
echo "This will take a while, get some coffee!"
echo "You will need to input your domain like 'domain.com' and the IP of your server correctly."
read -p "Please input your domain."$'\n' domain
read -p "Please input the IP of your server."$'\n' serverip
while true; do
    read -p "Start script? (Y/n)" yn
    case $yn in
        [Yy]* ) break;;
        [Nn]* ) exit;;
        * ) echo "Please answer yes or no.";;
    esac
done
apt-get update && apt-get upgrade -V -y && apt-get dist-upgrade -y
wget -O - http://nginx.org/keys/nginx_signing.key | apt-key add -
cat <<EOF > /etc/apt/sources.list.d/nginx.list
# Nginx (Mainline)
deb [arch=amd64] http://nginx.org/packages/mainline/ubuntu/ focal nginx
deb-src [arch=amd64] http://nginx.org/packages/mainline/ubuntu/ focal nginx
EOF
apt update && apt install -y nginx
useradd -m letsencrypt -s /bin/bash
usermod -a -G www-data letsencrypt
echo 'letsencrypt ALL=NOPASSWD: /bin/systemctl reload nginx.service' >> /etc/sudoers
su - letsencrypt -c 'curl https://get.acme.sh | sh'
mv /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default.conf_disabled 
sudo service nginx restart
mkdir -p /var/www/letsencrypt/.well-known/acme-challenge 
chown -R www-data:www-data /var/www/letsencrypt 
chmod -R 775 /var/www/letsencrypt 
mkdir -p /etc/letsencrypt/$domain/rsa
mkdir -p /etc/letsencrypt/$domain/ecc
chown -R www-data:www-data /etc/letsencrypt 
chmod -R 775 /etc/letsencrypt
cat <<EOF > /etc/nginx/conf.d/HttpGateway.conf
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name $domain;
 
    root /var/www;

    location ^~ /.well-known/acme-challenge {
        default_type text/plain;
        root /var/www/letsencrypt;
    }

	location / {
		return 301 https://\$host\$request_uri;
	}
}
EOF
sudo service nginx restart
echo "This a test if the webserver has been set up correctly." >> /var/www/letsencrypt/.well-known/acme-challenge/test.txt
echo "You might want to check your webserver, before generating certificates. Therefore a test page has been set up under 'http://$domain/.well-known/acme-challenge/test.txt'. Please view it in your browser, before proceeding."
while true; do
    read -p "Is everything set up correctly? (Y/n)" yn
    case $yn in
        [Yy]* ) break;;
        [Nn]* ) exit;;
        * ) echo "Please answer yes or no.";;
    esac
done
cd /opt
git clone https://github.com/asciimoo/searx.git
cd searx
PS3='Would you like to build from tags (recommended) or from master?'$'\n'
options=("tags" "master")
select opt in "${options[@]}"
do
    case $opt in
          "tags")
            git tag -l
            read -p "Which version of Searx would you like to install? (latest recommended)"$'\n' version
            git checkout tags/$version
            break
            ;;
        "master")
            echo "Building from master..."
             git checkout master
             break
            ;;
        *) echo "invalid option $REPLY";;
    esac
done
rm /var/www/letsencrypt/.well-known/acme-challenge/test.txt
sudo -u letsencrypt /home/letsencrypt/.acme.sh/acme.sh --issue -d $domain --keylength 4096 -w /var/www/letsencrypt --key-file /etc/letsencrypt/$domain/rsa/key.pem --ca-file /etc/letsencrypt/$domain/rsa/ca.pem --cert-file /etc/letsencrypt/$domain/rsa/cert.pem --fullchain-file /etc/letsencrypt/$domain/rsa/fullchain.pem --reloadcmd "sudo /bin/systemctl reload nginx.service"
sudo -u letsencrypt /home/letsencrypt/.acme.sh/acme.sh --issue -d $domain --keylength ec-384 -w /var/www/letsencrypt --key-file /etc/letsencrypt/$domain/ecc/key.pem --ca-file /etc/letsencrypt/$domain/ecc/ca.pem --cert-file /etc/letsencrypt/$domain/ecc/cert.pem --fullchain-file /etc/letsencrypt/$domain/ecc/fullchain.pem --reloadcmd "sudo /bin/systemctl reload nginx.service"
mkdir -p /etc/nginx/dhparams 
openssl dhparam -out /etc/nginx/dhparams/dhparams.pem 4096
mkdir -p /etc/nginx/snippets
cat <<EOF > /etc/nginx/snippets/ssl.conf
# Certificates used
# RSA
ssl_certificate /etc/letsencrypt/$domain/rsa/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/$domain/rsa/key.pem;

# ECC
ssl_certificate /etc/letsencrypt/$domain/ecc/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/$domain/ecc/key.pem;

# This should be ca.pem (certificate with the additional intermediate certificate)
# See here: https://certbot.eff.org/docs/using.html
ssl_trusted_certificate /etc/letsencrypt/$domain/ecc/ca.pem;

# Diffie-Hellman parameter, recommended 4096 bits
ssl_dhparam /etc/nginx/dhparams/dhparams.pem;

# Not using TLSv1 will break:
#	Android <= 4.4.40
#	IE <= 10
#	IE mobile <=10
# Removing TLSv1.1 breaks nothing else!
# TLSv1.3 is not supported by most clients, but it should be enabled.
ssl_protocols TLSv1.2 TLSv1.3;

# Prefer the SSL ciphers for ECDSA:
ssl_ciphers 'TLS-CHACHA20-POLY1305-SHA256:TLS-AES-256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384';
 
# Use multiple curves.
ssl_ecdh_curve secp521r1:secp384r1;

# Server should determine the ciphers, not the client
ssl_prefer_server_ciphers on;

# OCSP Stapling
# fetch OCSP records from URL in ssl_certificate and cache them
ssl_stapling on;
ssl_stapling_verify on;

# This is the IP if yout DNS-Server (in most cases: your router's IP)
resolver $serverip;

# SSL session handling
ssl_session_timeout 24h;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;
EOF
cat <<EOF > /etc/nginx/snippets/headers.conf
#
# Add headers to serve security related headers
#  
# HSTS (ngx_http_headers_module is required)
add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload;" always; 
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Robots-Tag none always;
add_header X-Download-Options noopen always;
add_header X-Permitted-Cross-Domain-Policies none always;
add_header Referrer-Policy no-referrer always;
add_header X-Frame-Options "SAMEORIGIN" always;

# Remove X-Powered-By, which is an information leak
fastcgi_hide_header X-Powered-By;
EOF
apt-get remove docker docker-engine docker.io
apt-get install apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
apt-get update
apt-get install -y docker-ce
sed -i -e "s/ultrasecretkey/`openssl rand -hex 32`/g" /opt/searx/searx/settings.yml
docker build -t searx .
docker run -d --name searx -p 8080:8080 --restart=always --log-driver none -e IMAGE_PROXY=True -e BASE_URL=https://$domain searx
cat <<EOF > /etc/nginx/conf.d/$domain.conf
server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;
        server_name $domain;

        # Include SSL configuration
        include /etc/nginx/snippets/ssl.conf;

        # Include headers
        include /etc/nginx/snippets/headers.conf;

        # Important: Disable error and access log, so that no IPs get logged
        access_log  off;
        error_log off;

        #
        # Configuration for Searx
        #

        location / {
                proxy_pass http://localhost:8080;
                proxy_set_header Host \$host;
                proxy_set_header X-Real-IP \$remote_addr;
                proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
                proxy_set_header X-Remote-Port \$remote_port;
                proxy_set_header X-Forwarded-Proto \$scheme;
                proxy_redirect off;
        }
}
EOF
sudo service nginx restart
echo "The installer finished and your searx instance should be up and running!"
