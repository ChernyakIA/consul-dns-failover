# Consul DNS Failover

> **Designed for bare-metal infra.**

This repo contains a light declarative DNS sync tool designed to bridge HashiCorp Consul service health registries and DNS-providers.

Run Automatically via `consul-template`, it ensures that target DNS A-records are dynamically updated in real-time based on live node availability, network health and custom failover policies.
