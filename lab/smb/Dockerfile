# A Samba server that still speaks the obsolete SMBv1 protocol and does not require signing,
# so reconscope reports both. It exposes a read-only guest share only.
FROM alpine:3.20
RUN apk add --no-cache samba-common-tools samba-server \
    && mkdir -p /srv/public /var/lib/samba/private /run/samba
COPY smb.conf /etc/samba/smb.conf
EXPOSE 445
CMD ["smbd", "--foreground", "--no-process-group", "--debug-stdout"]
