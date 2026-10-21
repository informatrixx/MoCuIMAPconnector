FROM python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright
COPY requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir -r /app/requirements.lock playwright==1.64.0 \
    && playwright install --with-deps chromium
COPY scripts/auth_browser_test.py /app/auth_browser_test.py
USER 10001:10001
ENTRYPOINT ["python", "/app/auth_browser_test.py"]
