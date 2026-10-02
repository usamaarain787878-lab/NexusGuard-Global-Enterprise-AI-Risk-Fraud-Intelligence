FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
EXPOSE 8501

# Command to run both or individual servers
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]