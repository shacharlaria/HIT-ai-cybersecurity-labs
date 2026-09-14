FROM python:3.12-slim

# Prevent Python from buffering stdout and stderr (immediate logs)
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install ML and statistical dependencies for Isolation Forest & Evaluator
RUN pip install --no-cache-dir numpy scikit-learn

# Copy detector engine and evaluation suite
COPY detector.py /app/detector.py
COPY evaluator.py /app/evaluator.py

CMD ["python", "/app/detector.py"]
