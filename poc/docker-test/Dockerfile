FROM ubuntu:22.04

#
# docker run --rm fileless-poc:latest /usr/local/bin/loader 2>&1
#

# Install netcat and bash (minimal toolset so the shell works)
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends netcat-openbsd bash && \
    rm -rf /var/lib/apt/lists/*

# Copy the pre-compiled, statically linked loader into the image
COPY loader /usr/local/bin/loader
RUN chmod +x /usr/local/bin/loader

# Labels for research identification
LABEL description="Fileless malware PoC loader — research use only"
LABEL technique="T1027.002 ExecutableInExecutable"

# Set the loader as the default command to run when the container starts
CMD ["/usr/local/bin/loader"]
