FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 RESEARCH_INDEX_DB=/data/research-index.sqlite
WORKDIR /app
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock
COPY app ./app
RUN sed -i 's|href="/static/|href="/torrent-sniffer/static/|; s|src="/static/|src="/torrent-sniffer/static/|' app/static/index.html \
    && sed -i 's|fetch(path, {|fetch(`/torrent-sniffer${path}`, {|' app/static/app.js
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
