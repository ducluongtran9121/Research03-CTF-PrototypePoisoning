FROM python:3.8.0

COPY src/. /srv
WORKDIR /srv
RUN apt update && apt-get install -y build-essential python3-dev python3-pip python3-setuptools python3-wheel python3-cffi libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
RUN pip install --upgrade pip
RUN pip install --default-timeout=100 -r requirements.txt
RUN mkdir static/output
COPY flag.txt /tmp/flag.txt

CMD [ "python", "./app.py"]
