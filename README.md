⚙️ Project Overview
Services
UI Service (cyberpulse-ui)

Built with Flask + HTMX/Tailwind for interactivity

Users can:

View recent threats

Filter by type (e.g., IOC type, severity, date, tags, etc.)

API Service (cyberpulse-api)

Exposes endpoints like /api/threats?type=IP&date=last7days

Fetches from MongoDB

Communicates with the background threat-ingestion service

Ingestion Service (cyberpulse-ingestor)

Periodically fetches recent AlienVault OTX threat indicators

Stores them in MongoDB

Adds trace metadata (for OpenTelemetry)

Database

MongoDB (threat storage)

Tracing

OpenTelemetry setup across all 3 services

Traces visualized in OpenObserve





mongo
threatintel
use cyberpulse
db.threats.countDocuments()
db.threats.find().limit(3).pretty()

mongosh
threatintel
use threatintel
db.threats.countDocuments()
db.threats.find().limit(3).pretty()


docker-compose build --no-cache
docker-compose up -d
docker-compose up --build


docker-compose down
docker-compose up -d


Get Token
select data sources
click on Traces(OpenTelemetry)
