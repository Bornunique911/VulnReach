docker compose -f docker-compose.yml -f docker-compose.runtime.yml down --remove-orphans
docker compose -f docker-compose.yml -f docker-compose.runtime.yml build --no-cache
docker compose -f docker-compose.yml -f docker-compose.runtime.yml up