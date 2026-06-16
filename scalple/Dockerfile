FROM python:3.12-slim

WORKDIR /app

COPY scalple/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Bring in the middleware package and the demo scripts.
COPY scalple /app/scalple
COPY demo /app/demo

# The demo container waits for the DB, then runs the full narrative and exits.
CMD ["python", "demo/run_demo.py"]
