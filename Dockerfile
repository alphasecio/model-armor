# Stage 1: install dependencies
FROM python:3.13-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /install
COPY requirements.txt .
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt

# Stage 2: runtime
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /usr/src/app

COPY --from=builder /install /usr/local
COPY core.py cloudrun_app.py ./

RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8501

CMD ["sh", "-c", "exec streamlit run cloudrun_app.py --server.port=${PORT:-8501} --server.headless=true --server.maxUploadSize=10 --browser.gatherUsageStats=false"]
