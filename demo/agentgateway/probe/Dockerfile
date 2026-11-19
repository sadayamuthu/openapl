FROM python:3.11.11-slim
RUN pip install --no-cache-dir "grpcio==1.85.*" "xds-protos==1.85.*"
WORKDIR /app
COPY probe.py .
CMD ["python", "-u", "probe.py"]
