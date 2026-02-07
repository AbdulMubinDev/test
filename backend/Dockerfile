FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y build-essential libpq-dev && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

ENV DJANGO_SETTINGS_MODULE=core.settings

# Run Gunicorn with security hardening and config file
CMD ["sh", "-c", "python manage.py migrate && gunicorn core.wsgi:application -c /app/gunicorn.conf.py"]
