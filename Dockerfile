FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend ./backend
COPY frontend ./frontend
WORKDIR /app/backend
# Di dalam container server harus mendengarkan 0.0.0.0; di host tetap dipetakan ke 127.0.0.1 (lihat docker-compose.yml)
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
