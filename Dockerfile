FROM python:3.13-slim

WORKDIR /app

RUN pip config set global.index-url https://mirrors.ustc.edu.cn/pypi/simple

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py fallback.pac fallback_ip_cn.json fallback_domains.json ./
COPY gfwlist/ ./gfwlist/
COPY flora/ ./flora/
COPY whitelist/ ./whitelist/

RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8080

CMD ["python3", "app.py"]
