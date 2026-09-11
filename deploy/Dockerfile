# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /src
COPY pyproject.toml README.vpn.md LICENSE ./
COPY vpn ./vpn
COPY relay ./relay
RUN python -m venv /venv && /venv/bin/pip install --no-compile .

FROM python:3.12-slim
ENV PATH=/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd --system relay && useradd --system --gid relay --no-create-home relay
COPY --from=build /venv /venv
USER relay
EXPOSE 8765
ENTRYPOINT ["ws-vpn-relay"]
CMD ["--host", "0.0.0.0", "--port", "8765", "--cert", "/run/secrets/tls.crt", "--key", "/run/secrets/tls.key"]
