FROM python:3.15.2-slim
RUN pip install --no-cache-dir "mcp>=1.23,<2"
WORKDIR /app
COPY payments.py crm.py ./
# Choose the server with the compose `command` (python payments.py | python crm.py) or the build arg.
ARG SERVER=payments.py
ENV SERVER=${SERVER}
CMD ["sh", "-c", "python $SERVER"]
