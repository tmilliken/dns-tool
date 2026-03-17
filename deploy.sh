#!/bin/bash
# DNScan Deployment Script
# Run this on your VPS to set up the application
# Usage: bash deploy.sh yourdomain.com

set -e
DOMAIN=${1:-"yourdomain.com"}
APP_DIR="/var/www/dns-tool"

echo "==> Installing system dependencies..."
apt-get update -q
apt-get install -y python3 python3-pip python3-venv nginx certbot python3-certbot-nginx

echo "==> Creating app directory..."
mkdir -p $APP_DIR/frontend
mkdir -p $APP_DIR/backend

echo "==> Copying files..."
cp -r backend/* $APP_DIR/backend/
cp -r frontend/* $APP_DIR/frontend/

echo "==> Setting up Python virtual environment..."
cd $APP_DIR
python3 -m venv venv
venv/bin/pip install -r backend/requirements.txt

echo "==> Setting permissions..."
chown -R www-data:www-data $APP_DIR

echo "==> Configuring nginx..."
sed "s/yourdomain.com/$DOMAIN/g" nginx.conf > /etc/nginx/sites-available/dnsscan
ln -sf /etc/nginx/sites-available/dnsscan /etc/nginx/sites-enabled/dnsscan
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

echo "==> Setting up SSL with Let's Encrypt..."
certbot --nginx -d $DOMAIN -d www.$DOMAIN --non-interactive --agree-tos -m admin@$DOMAIN

echo "==> Installing systemd service..."
sed "s/yourdomain.com/$DOMAIN/g" dnsscan.service > /etc/systemd/system/dnsscan.service
systemctl daemon-reload
systemctl enable dnsscan
systemctl start dnsscan

echo ""
echo "✅ Deployment complete!"
echo "   Your DNS tool is live at https://$DOMAIN"
echo ""
echo "   Useful commands:"
echo "   systemctl status dnsscan    # Check backend status"
echo "   journalctl -u dnsscan -f    # View backend logs"
echo "   systemctl reload nginx      # Reload nginx config"
