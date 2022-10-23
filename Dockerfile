FROM python:3.10
WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
COPY src /app
EXPOSE 8080
CMD waitress-serve --host 0.0.0.0 app:app