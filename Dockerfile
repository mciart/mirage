FROM rust:alpine3.22 AS builder

# Install pre-requisites
RUN apk add build-base gcompat jemalloc-dev

# Create a new directory for our application
WORKDIR /tmp/mirage-build

# Copy the source code into the container
COPY . .

# Build the application
ARG FEATURES="jemalloc,offload"
RUN cargo build --release --workspace --no-default-features --features "${FEATURES}" --exclude mirage-gui

FROM alpine:3.22 AS runner

# Create needed directories
RUN mkdir -p /etc/mirage

# Install glibc
RUN apk add gcompat jemalloc libcap-setcap

# Copy the binary from the builder stage
COPY --from=builder /tmp/mirage-build/target/release/mirage-client /tmp/mirage-build/target/release/mirage-server /tmp/mirage-build/target/release/mirage-users /usr/local/bin/

# Add a non-root user
RUN addgroup -S mirage && adduser -S mirage -G mirage
RUN chown -R mirage:mirage /usr/local/bin/mirage-client /usr/local/bin/mirage-server /usr/local/bin/mirage-users

# Add required capabilities to executables
RUN setcap \
    'cap_net_admin,cap_net_bind_service=+ep' /usr/local/bin/mirage-client \
    'cap_net_admin,cap_net_bind_service=+ep' /usr/local/bin/mirage-server \
    'cap_net_admin=+ep' /bin/busybox

# Run under a non-root account
USER mirage

# Set the working directory
WORKDIR /usr/srv/mirage
