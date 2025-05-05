FROM python:3.11-slim

WORKDIR /app

RUN apt-get update

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "database:app", "--host", "0.0.0.0", "--port", "8000"]
