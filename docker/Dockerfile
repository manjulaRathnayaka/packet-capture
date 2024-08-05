FROM python:3.9-slim

RUN pip install pypcap dpkt

COPY capture.py /app/capture.py

CMD ["python", "/app/capture.py"]

