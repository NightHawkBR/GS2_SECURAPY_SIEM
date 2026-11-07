# SecuraPy Platform — imagem da API + dashboard + servidor de alertas (Módulo F · Aula 11)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# nunca rodar como root dentro do contêiner
RUN useradd --create-home --uid 10001 securapy && chown -R securapy /app
USER securapy

EXPOSE 5000 9999

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/api/saude', timeout=2)"

# 1 worker: o servidor TCP de alertas vive dentro do processo da API
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "8", "api.app:criar_app()"]
