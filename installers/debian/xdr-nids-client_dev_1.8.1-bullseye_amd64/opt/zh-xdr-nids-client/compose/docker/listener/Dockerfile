FROM python:3.8.13-slim-buster

# Enabling the environment variable for capturing python output.
ENV PYTHONUNBUFFERED 1
ENV DEBIAN_FRONTEND=noninteractive

COPY requirements.txt /app/requirements.txt
WORKDIR /app

RUN apt update && \
    apt upgrade -y && \
    apt install tshark gcc -y && \
    apt autoremove -y && \
    pip3 install -r requirements.txt && \
	mkdir -p /var/log/data/raw_data/listener/

COPY dist/ /assets
WORKDIR /assets

RUN python3 compile.py build_ext --inplace && \
    rm listener.py listener.c && \
    mv listener.* listener.so && \
    mv *.so *.py *.ini *.txt /app/ && \
    rm -r build 

WORKDIR /app

CMD python3 /app/entrypoint.py
