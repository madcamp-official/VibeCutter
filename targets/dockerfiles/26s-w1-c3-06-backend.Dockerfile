FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/

WORKDIR /app/backend/src/custom_api
EXPOSE 5000
CMD ["sh", "-c", "python -c \"import account; account.Base.metadata.create_all(account.engine)\" && python seed_news.py && python seed_prices.py && python seed_stock_params.py && python seed_quiz.py && python -c \"import main; main.app.run(host='0.0.0.0', port=5000, threaded=True)\""]
