# Reverse Proxy Setup Guide

This guide covers setting up Doorman behind Nginx on a fresh Linux cloud instance.

**Configuration:**
- `https://app.doorman.dev` → frontend (localhost:3000)
- `https://api.doorman.dev` → backend (localhost:3001)

## Prerequisites

- Fresh Linux instance (Ubuntu/Debian)
- DNS records for `app.doorman.dev` and `api.doorman.dev` pointing to your server's IP
- Ports 80 and 443 open

## Step 1: Install Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# Install Nginx and Certbot
sudo apt install -y nginx certbot python3-certbot-nginx
```

## Step 2: Clone and Configure Doorman

```bash
mkdir ~/app
cd ~/app
git clone https://github.com/doorman-dev/doorman.git
cd doorman
git checkout {version}

# Copy and edit environment file
cp .env.example .env
nano .env
```

Edit `.env` with your production settings:

```bash
ENV=production
HTTPS_ONLY=true
JWT_SECRET_KEY=<generate with: openssl rand -base64 48>
DOORMAN_ADMIN_EMAIL=admin@yourdomain.com
DOORMAN_ADMIN_PASSWORD=<strong-password-min-12-chars>

# Cookie settings
COOKIE_DOMAIN=doorman.dev
COOKIE_SAMESITE=Strict
```

## Step 3: Configure Nginx

Create `/etc/nginx/sites-available/doorman`:

```bash
sudo nano /etc/nginx/sites-available/doorman
```

Paste this configuration:

```nginx
# Frontend
server {
    listen 80;
    server_name app.doorman.dev;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}

# Backend API
server {
    listen 80;
    server_name api.doorman.dev;

    location / {
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        proxy_read_timeout 300s;
    }
}
```

Enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/doorman /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default  # Remove default site
sudo nginx -t
sudo systemctl restart nginx
```

## Step 4: Get SSL Certificates

```bash
sudo certbot --nginx -d app.doorman.dev -d api.doorman.dev
```

Follow the prompts. Certbot will automatically configure HTTPS and set up auto-renewal.

## Step 5: Start Doorman

```bash
cd ~/app/doorman
docker compose build
docker compose up -d
```

Verify services are running:

```bash
docker compose ps
curl http://localhost:3001/platform/monitor/liveness
```

## Step 6: Verify

1. Visit `https://app.doorman.dev` — should load the login page
2. Visit `https://api.doorman.dev/platform/monitor/liveness` — should return `{"status":"ok"}`
3. Log in with your admin credentials

## Firewall (Recommended)

```bash
sudo ufw allow 22
sudo ufw allow 80
sudo ufw allow 443
sudo ufw enable
```

## Troubleshooting

**502 Bad Gateway:**
```bash
# Check if Doorman is running
docker compose ps
docker compose logs doorman
```

**SSL certificate issues:**
```bash
sudo certbot certificates
sudo certbot renew --dry-run
```

**Check Nginx logs:**
```bash
sudo tail -f /var/log/nginx/error.log
```

**Restart everything:**
```bash
sudo systemctl restart nginx
docker compose restart
```
