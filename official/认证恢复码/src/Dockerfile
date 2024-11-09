FROM rust:1.82-bookworm AS builder

WORKDIR /code
COPY web/ /code
RUN cargo build --release

FROM ustclug/debian:bookworm
WORKDIR /app/
COPY --from=builder /code/target/release/web-auth /app/web-auth
COPY --from=builder /code/static/ /app/static/
COPY --from=builder /code/templates/ /app/templates/
# RUN echo "Submit your payload to get real flag1 on server!" > /flag1 && \
#     echo "Submit your payload to get real flag2 on server!" > /flag2
USER nobody
CMD ["/app/web-auth"]
