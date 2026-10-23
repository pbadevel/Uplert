# Single static scratch image, ~10 MB.
FROM scratch

WORKDIR /etc/uplert

COPY bin/uplert /usr/local/bin/uplert
COPY configs/config.yaml /etc/uplert/config.yaml

# non-interactive default: agent loop
ENTRYPOINT ["/usr/local/bin/uplert"]
CMD ["run", "--config", "/etc/uplert/config.yaml"]
