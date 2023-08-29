FROM python:3.8-slim

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

COPY . .

RUN git clone https://github.com/MugoSquero/LibreTotal .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "--insecure", "0.0.0.0:8000"]
