FROM python:3.8.13-slim-buster

ENV PYTHONUNBUFFERED 1
ENV DEBIAN_FRONTEND=noninteractive

COPY dist/ /app
WORKDIR /app

RUN apt update && apt upgrade -y && apt install tshark -y && pip3 install -r requirements.txt && apt clean && apt autoremove -y

CMD python3 /app/main.py