FROM python:3.13-slim

WORKDIR /app
COPY pyproject.toml ./
COPY dianoia_auth/ dianoia_auth/
# The test extra so `pytest tests/` runs in the image.
RUN pip install --no-cache-dir ".[test]"
COPY tests/ tests/
COPY scripts/ scripts/

EXPOSE 8002
CMD ["dianoia-auth", "--host", "0.0.0.0", "--port", "8002"]
