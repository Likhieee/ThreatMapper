FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 80

CMD ["python3", "-m", "uvicorn", "backend:app", "--host", "0.0.0.0", "--port", "80"]