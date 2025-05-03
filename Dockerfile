FROM python:3.13-alpine

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements_docker.txt

RUN adduser -D appuser && chown -R appuser:appuser /app
USER appuser

CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]