FROM python:3.7
ENV PYTHONUNBUFFERED 0

RUN mkdir /code
WORKDIR /code

ADD . /code/
RUN pip install -e .[aws,database,development]

RUN mkdir /tox
ENV TOX_WORK_DIR='/tox'
