FROM postgres:16

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

RUN mkdir -p /etc/postgresql
COPY pg_hba.conf /etc/postgresql/pg_hba.conf
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]