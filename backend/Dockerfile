FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Create a non-root user for security (Least Privilege)
RUN adduser --system --group --disabled-password --home /app appuser \
    && chown -R appuser:appuser /app

USER appuser
ENV HOME=/app

# Create venv and add to PATH to ensure clean package isolation 
RUN python -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

COPY --chown=appuser:appuser requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appuser . .

EXPOSE 8000

ENV PYTHONPATH="/app"

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
