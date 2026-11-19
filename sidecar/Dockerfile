# Build from the repository root:
#   docker build -f sidecar/Dockerfile -t openapl-sidecar:dev .
FROM python:3.11.11-slim

WORKDIR /app
COPY sdk/ /app/sdk/
COPY sidecar/ /app/sidecar/
RUN pip install --no-cache-dir ./sdk ./sidecar

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin openapl
USER openapl

ENV OPENAPL_POLICY_DIR=/policies
EXPOSE 8081 9000

HEALTHCHECK CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8081/healthz', timeout=2)"

ENTRYPOINT ["openapl-sidecar"]
CMD ["serve"]
