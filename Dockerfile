FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p uploads encrypted_files

EXPOSE 5000

ENV FLASK_APP=app.py

# Runtime config is provided via .env or docker-compose environment section
# Do NOT hardcode SECRET_KEY or ENCRYPTION_KEY here

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
