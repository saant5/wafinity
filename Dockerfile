FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x start.sh

ENV PORT=5000
ENV BACKEND_URL=http://127.0.0.1:5001

EXPOSE 5000

CMD ["./start.sh"]