#!/usr/bin/env bash
set -eo pipefail

log() {
    local LEVEL="info"
    [ "$#" -eq 1 ] || { LEVEL="$1"; shift; }
    local MSG="$1"
    local TS="$(date --iso-8601=ns | sed 's/[,\.]\([0-9][0-9][0-9]\).\+$/.\1/')"
    case "$LEVEL" in
        info)  echo "$TS * $MSG" ;;
        err*)  echo "$TS * ERROR: $MSG" ;;
        warn*) echo "$TS * WARNING: $MSG" ;;
        *)     echo "$TS * ${LEVEL}: $MSG" ;;
    esac
}

_sed() {
    local FN TMP="$(mktemp)"
    for FN; do :; done;
    sed "$@" > "$TMP"
    cat "$TMP" > "$FN"
    rm -rf "TMP"
}

enabled() {
    local V="ALLOW_${1^^}"
    [ -n "${!V}" ] && [ "${!V}" -eq 1 ] && return 0 || return 1
}
disabled() { enabled "$1" && return 1 || return 0; }

log "Entrypoint script for IPv6 support started."

ifconfig

MY_HOSTNAME="$HOSTNAME"
MY_IPV6="$(ip -6 addr show dev eth0 | grep inet6 | grep -oE "([0-9a-fA-F]{1,4}::?[0-9a-fA-F:]*)" | awk '{print $1}' | sed 's#/.*$##')"

# Remove IPv6 DNS addresses, as they come from uplink provider and may
# cause instability in docker environment
log "Removing IPv6 DNS addresses from /etc/resolv.conf"
_sed -E '/^nameserver [[:xdigit:]:]+$/d' /etc/resolv.conf

# By default the file /etc/nsswitch.conf contains:
#     hosts:      files dns myhostname
# This can result in a situation where the hostname resolves to
# an unexpected ip address. To avoid that, we set the field 'host' to fixed
# value 'files dns'. This makes name resolution predictable. Hostname can be
# resolved only via /etc/hosts file or via DNS.
log "Setting 'files dns' for 'hosts' in /etc/nsswitch.conf"
_sed -E 's/^(hosts:[[:space:]]+).+$/\1files dns/' /etc/nsswitch.conf

# pre-checks
if disabled lo_ipv4 && enabled dns_ipv4; then
    log warn "loopback IPv4 disabled, but IPv4 DNS server is enabled. This will lead to non-working DNS. Force disabling IPv4 DNS."
    ALLOW_DNS_IPV4=0
fi

if enabled hostnames && disabled dns_ipv4 && disabled dns_ipv6; then
    log warn "hostnames are enabled, but DNS servers are disabled. This will lead to connection issues. Force disabling hostnames."
    ALLOW_HOSTNAMES=0
fi

if disabled hostnames; then
    log "Hostnames: disabled"
    while read -r a; do
        k="${a%%=*}"
        v="${a#*=}"
        if r="$(getent hosts "$v" | awk '{print $1}' | grep :)"; then
            export "${k}=${r}"
            log "  set ${k}=${r} (old value: ${v})"
        fi
    done < <(env)
    unset a k v r
    PUBLIC_HOSTNAME="$MY_IPV6"
    export PUBLIC_HOSTNAME
    log "  set PUBLIC_HOSTNAME=$PUBLIC_HOSTNAME"
    log "  set hostname in /etc/hostname as '$MY_IPV6'"
    echo "$MY_IPV6" >/etc/hostname
else
    log "Hostnames: enabled"
fi

if disabled ipv4; then
    log "External IPv4: disabled"
    ip -4 addr flush dev eth0
    _sed -E "/^[[:digit:].]+[[:space:]]+$MY_HOSTNAME$/d" /etc/hosts
else
    log "External IPv4: enabled"
fi

if disabled lo_ipv4; then
    log "Loopback IPv4: disabled"
    ip -4 addr flush dev lo
    _sed -E '/^[[:digit:].]+[[:space:]]+localhost$/d' /etc/hosts
else
    log "Loopback IPv4: enabled"
fi

if disabled dns_ipv4; then
    log "DNS IPv4: disabled"
    _sed -E '/^nameserver [[:digit:].]+$/d' /etc/resolv.conf
else
    log "DNS IPv4: enabled"
fi

if ! disabled dns_ipv6; then
    log "DNS IPv6: enabled"
    # start micro-dns service in background
    (
        ls -liart /micro-dns-service/*
        PIPE_NAME="/micro-dns-service/$MY_HOSTNAME"
        [ -p "$PIPE_NAME" ] || mkfifo "/micro-dns-service/$MY_HOSTNAME"
        while :; do
            if read -r line < "$PIPE_NAME"; then
                if ! grep --silent --fixed-strings "$line" /etc/hosts; then
                    log "[micro-dns] register new host: $line"
                    echo "$line" >> /etc/hosts
                    SOURCE_HOST="${line##* }"
                    echo "$MY_IPV6 $MY_HOSTNAME" >"/micro-dns-service/$SOURCE_HOST" &
                fi
            fi
        done
    ) &
    # announce my host/ip to all available containers
    for i in /micro-dns-service/*; do
        if [ "$(basename "$i")" != "$MY_HOSTNAME" ] && [ -p "$i" ]; then
            # send in background to not block this script when there is no pipe reader present
            echo "$MY_IPV6 $MY_HOSTNAME" >"$i" &
        fi
    done
else
    log "DNS IPv6: disabled"
    log "  remove '$MY_HOSTNAME' from /ets/hosts"
    _sed -E "/^[[:xdigit:]:]+[[:space:]]+$MY_HOSTNAME$/d" /etc/hosts
fi

log "Entrypoint script for IPv6 support finished!"
ifconfig
