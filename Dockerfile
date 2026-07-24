FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml setup.py README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir ".[memory]" uvicorn fastapi

COPY cloud-run/main.py ./main.py

EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
