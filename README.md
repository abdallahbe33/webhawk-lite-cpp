# WebHawk Lite C++

WebHawk Lite C++ is a lightweight security middleware project written in C++.

The final project will work like a small Web Application Firewall:

```text
Client → WebHawk Lite C++ → Real Backend

## Part 02 - PostgreSQL database

This part adds PostgreSQL using Docker Compose and creates the five main WebHawk Lite database tables.

### Start database

```bash
docker compose up -d