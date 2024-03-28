FROM ubuntu

ENV PYTHONUNBUFFERED 1

RUN apt update && apt upgrade -y && apt install python3-pip -y && apt autoremove && apt clean 
RUN pip3 install pandas && \
    pip3 install cython

COPY dist/ /assets
WORKDIR /assets

RUN python3 compile.py build_ext --inplace && \
    rm normalizer.py normalizer.c && \
    mv normalizer.* normalizer.so && \
    mkdir /app &&  \
    mv *.so *.py *.ini /app/ && \
    rm -r build

WORKDIR /app

CMD python3 entrypoint.py