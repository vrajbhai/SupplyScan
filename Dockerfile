FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=7860

WORKDIR /app

# Install system dependencies needed for compiling packages (like yara)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy pyproject.toml and requirements
COPY requirements.txt pyproject.toml README.md ./

# Install python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY supplyscan/ ./supplyscan/
COPY tests/ ./tests/

# Install the supplyscan package in editable/local mode
RUN pip install --no-cache-dir -e .

# Expose the default port (Hugging Face Spaces uses 7860, Render uses PORT env var)
EXPOSE 7860

# Run uvicorn server
CMD ["sh", "-c", "uvicorn supplyscan.dashboard.app:app --host 0.0.0.0 --port ${PORT:-7860}"]
