# The receiver, as an image somebody can pull instead of a repository somebody
# has to build.
#
# FROM scratch, and that is not minimalism for its own sake. `trailryx-ingest`
# has zero third-party crates, so a musl build of it is one statically linked
# file with nothing underneath it to patch, to scan, or to explain to whoever
# runs this next to their own workloads. An image with a base distribution in it
# would carry a package manager and a CVE feed that have nothing to do with what
# this program does.
#
# The binary is built OUTSIDE this file, by `.github/workflows/release.yml`, and
# copied in. Building inside the image would mean a Rust toolchain in the build
# context and no way to publish the same bytes to the release page and the
# registry. The bytes a user downloads and the bytes in this image are the same
# bytes, and that is checkable: both are listed in `SHA256SUMS` on the release.
#
# The context therefore holds one directory per architecture, named the way
# buildx names them, so one Dockerfile covers both without a second file or a
# per-platform build argument:
#
#   ctx/amd64/trailryx-ingest
#   ctx/arm64/trailryx-ingest
#
# By hand, for one architecture:
#   cargo build --release --locked --target x86_64-unknown-linux-musl --bin trailryx-ingest
#   mkdir -p ctx/amd64 && cp target/x86_64-unknown-linux-musl/release/trailryx-ingest ctx/amd64/
#   docker build -f Dockerfile ctx

FROM scratch

# Set by buildx for every platform it builds, and the reason this file does not
# need a build argument of its own. Declared here so the COPY below can read it:
# an undeclared TARGETARCH expands to nothing and the COPY silently takes the
# wrong path.
ARG TARGETARCH

COPY ${TARGETARCH}/trailryx-ingest /trailryx-ingest

# Numeric, because there is no /etc/passwd in a scratch image to resolve a name
# against. 65532 is the conventional "nonroot" id, so a cluster that pins
# runAsUser to it does not have to special-case this image. Kubernetes Pod
# Security `restricted` requires runAsNonRoot, and an image that declares root
# fails that check before anybody reads the manifest.
USER 65532:65532

# OTLP/HTTP. The server binds what `--bind` says and nothing listens until it is
# told to, so this is documentation for whoever writes the Service rather than a
# default that opens anything.
EXPOSE 4318

ENTRYPOINT ["/trailryx-ingest"]
CMD ["--bind", "0.0.0.0:4318"]
