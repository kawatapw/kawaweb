FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /srv/root

RUN apt update && apt install --no-install-recommends -y \
    git curl build-essential \
    nginx \
    && rm -rf /var/lib/apt/lists/* 

#RUN git submodule init && git submodule update

COPY ext/requirements.txt ./
#RUN python3.9 -m pip install python-dotenv
RUN python3.11 -m pip install -U pip setuptools
RUN python3.11 -m pip install -r requirements.txt

# Copy your service files to the appropriate location
COPY . .

ENTRYPOINT [ "scripts/start_server.sh" ]
