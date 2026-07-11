FROM python:3.12-slim

WORKDIR /src
COPY pyproject.toml README.md ./
COPY trustchain ./trustchain
RUN pip install --no-cache-dir .

VOLUME /var/lib/tc-witness
EXPOSE 8747

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD \
  python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8747/healthz', timeout=2)" || exit 1

ENTRYPOINT ["tc-witness"]
CMD ["serve", "--key", "/var/lib/tc-witness/witness.key.json", \
     "--state", "/var/lib/tc-witness/observed.json", \
     "--host", "0.0.0.0", "--port", "8747", "--require-consistency"]
