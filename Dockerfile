FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy pyproject.toml first so deps are cached in a layer
COPY pyproject.toml .
COPY src/ src/

# Install all declared dependencies via pyproject.toml
RUN pip install --no-cache-dir -e .

# Copy the rest of the project (data, docs, etc.)
COPY . .

# Pre-build the knowledge base
RUN python src/crateshield/llm/kb_builder.py || true

# Expose backend port
EXPOSE 8000

# Run FastAPI server
CMD ["uvicorn", "crateshield.api:app", "--host", "0.0.0.0", "--port", "8000"]
