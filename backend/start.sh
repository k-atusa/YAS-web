#!/bin/sh
set -e

# Setup Tor config for control port
echo "ControlPort 9051" > /etc/tor/torrc
echo "CookieAuthentication 0" >> /etc/tor/torrc
echo "User debian-tor" >> /etc/tor/torrc
echo "DataDirectory /var/lib/tor" >> /etc/tor/torrc

# Create Tor data directory with proper permissions
mkdir -p /var/lib/tor
chown -R debian-tor:debian-tor /var/lib/tor
chmod 700 /var/lib/tor

# Run Tor in background (it will drop privileges to debian-tor)
tor -f /etc/tor/torrc &

# Wait for Tor control port to open
sleep 2

# Run Node.js server
exec node dist/server.js
