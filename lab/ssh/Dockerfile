# An SSH server configured to also offer some deprecated algorithms, so reconscope's hygiene
# checks have something to report. It accepts no logins (password auth is disabled).
FROM alpine:3.20
RUN apk add --no-cache openssh \
    && ssh-keygen -A \
    && adduser -D -s /sbin/nologin lab
COPY sshd_config /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
