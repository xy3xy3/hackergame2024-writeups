FROM ustclug/debian:12

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt -y upgrade && \
    apt install -y python3 python3-flask

COPY /web /web
WORKDIR /web
USER nobody

CMD [ "./run.sh" ]
