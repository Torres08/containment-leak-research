# =============================================================================
# Dockerfile — nginx Web Server
# Vilnius University MICAC — Containment Leak Research
# =============================================================================
# Mirrors the Apptainer container.def companion file.
# Both are based on the official Apptainer nginx documentation example:
#   https://apptainer.org/docs/user/main/running_services.html#nginx-hello-world-in-apptainer
#
# The canonical Apptainer pattern is:
#
#   Bootstrap: docker
#   From: nginx
#   %startscript
#       nginx
#
# Docker equivalent:
#
#   FROM nginx:alpine
#   CMD ["nginx", "-g", "daemon off;"]
#
# This file extends that minimal pattern with a web page and metadata labels.
#
# Build:  docker build -t fileless-poc-victim:latest deployment/
# Start:  docker run -d -p 80:80 --name victim-webapp fileless-poc-victim:latest
# Stop:   docker stop victim-webapp
# Test:   curl localhost
# =============================================================================

FROM nginx:alpine

# COPY — embeds the shared html content (same source as container.def %files)
COPY html/index.html /usr/share/nginx/html/index.html

# LABEL — image metadata (mirrors %labels in container.def)
LABEL Author="Juan Luis Torres Ramos"
LABEL Institution="Vilnius University — MICAC Research Group"
LABEL Application="nginx Web Application"
LABEL Version="1.0"
LABEL Base="nginx:alpine"
LABEL Reference="https://apptainer.org/docs/user/main/running_services.html"

EXPOSE 80

# CMD — runs nginx in foreground (mirrors %startscript in container.def)
# "daemon off;" prevents nginx from forking to background, keeping the container alive.
CMD ["nginx", "-g", "daemon off;"]
