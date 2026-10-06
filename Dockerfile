FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY graphops ./graphops
COPY dashboard ./dashboard
EXPOSE 8000
# ${PORT:-8000}: Render / Railway / Fly / Koyeb inject PORT; default for local docker run
CMD ["sh", "-c", "uvicorn graphops.api.server:app --host 0.0.0.0 --port ${PORT:-8000}"]
