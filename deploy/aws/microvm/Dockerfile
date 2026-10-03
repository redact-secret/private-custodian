# Tools-only synthetic health probe. Deliberately refuses every evaluation job.
# Explicit ARM64 manifests pin both the compiler and the AWS container base.
FROM rust@sha256:63086e1fb45a56fe0ab75d77e23323a96ec07f1bb74cb0793516280271c852bd AS build
WORKDIR /build
COPY health.rs .
RUN rustc --version && rustc --edition=2021 -C opt-level=2 -C target-feature=+crt-static health.rs -o health

FROM public.ecr.aws/lambda/microvms@sha256:73a51c3b6eb9f116f75ea89395c9dac70760c172e653121052863ff1f71072af
COPY --from=build /build/health /app/health
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/app/health"]
