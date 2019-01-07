FROM python:2.7

ADD ./VulntoES.py /opt/OffensiveELK/
ADD ./FileMonitor.py /opt/OffensiveELK/
ADD ./requirements.txt /opt/OffensiveELK/
ADD ./docker-entrypoint.sh /opt/OffensiveELK/
ADD ./dashboard.json /opt/OffensiveELK/
WORKDIR /opt/OffensiveELK/

RUN pip install -r requirements.txt

CMD ["/bin/bash", "./docker-entrypoint.sh"]
