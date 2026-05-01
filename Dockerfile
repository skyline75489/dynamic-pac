FROM mcr.microsoft.com/azurelinux/base/python:3.12

RUN tdnf update -y && tdnf install -y shadow-utils && tdnf clean all

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py fallback.pac ./

RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8080

CMD ["python", "app.py"]
