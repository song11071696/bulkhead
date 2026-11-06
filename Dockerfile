FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 BULKHEAD_DATA=/data
COPY pyproject.toml README.md LICENSE ./
COPY bulkhead ./bulkhead
COPY fixtures ./fixtures
COPY scripts ./scripts
RUN pip install --no-cache-dir -e .
VOLUME /data
EXPOSE 8787
# BULKHEAD_MODE=replay works with no key (recorded responses); set CLOCKED_API_KEY for live checks.
CMD ["bulkhead", "serve", "--host", "0.0.0.0", "--port", "8787"]
