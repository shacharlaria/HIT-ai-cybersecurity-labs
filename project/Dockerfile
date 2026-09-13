FROM python:3.12-slim

WORKDIR /app

# התקנת הספריות הנדרשות למודל ה-Isolation Forest והחישובים הסטטיסטיים
RUN pip install --no-cache-dir numpy scikit-learn

COPY detector.py /app/detector.py

CMD ["python", "/app/detector.py"]