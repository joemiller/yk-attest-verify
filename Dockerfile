FROM scratch

COPY yk-attest-verify /yk-attest-verify

ENTRYPOINT ["/yk-attest-verify"]