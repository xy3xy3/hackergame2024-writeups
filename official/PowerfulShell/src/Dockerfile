FROM ubuntu:22.04

WORKDIR /players
RUN useradd -ms /bin/bash players
RUN usermod -d /players players

RUN apt-get install -y bash && \
    apt-get clean

COPY ./PowerfulShell.sh /players/PowerfulShell.sh
RUN chmod -R 755 /players/PowerfulShell.sh
USER players

CMD ["/players/PowerfulShell.sh"]