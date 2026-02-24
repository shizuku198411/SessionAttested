FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ARG DEV_UID=1000
ARG DEV_GID=1000

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       openssh-server \
       sudo \
       ca-certificates \
       vim \
       less \
       git \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd

RUN set -eux; \
    uid_user="$(getent passwd "${DEV_UID}" | cut -d: -f1 || true)"; \
    if ! getent group "${DEV_GID}" >/dev/null; then \
      groupadd -g "${DEV_GID}" dev; \
    fi; \
    if id -u dev >/dev/null 2>&1; then \
      usermod -u "${DEV_UID}" -g "${DEV_GID}" -s /bin/bash dev; \
    elif [ -n "${uid_user}" ]; then \
      if [ "${uid_user}" != "dev" ]; then \
        usermod -l dev -d /home/dev -m "${uid_user}"; \
      fi; \
      usermod -g "${DEV_GID}" -s /bin/bash dev; \
    else \
      useradd -m -u "${DEV_UID}" -g "${DEV_GID}" -s /bin/bash dev; \
    fi; \
    echo 'dev:devpass' | chpasswd; \
    usermod -aG sudo dev

RUN sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && printf '\nUsePAM yes\nPubkeyAuthentication yes\n' >> /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
