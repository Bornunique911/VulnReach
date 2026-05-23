# eclipse-temurin:17-jdk ships OpenJDK with hotspot USDT probes available.
# -XX:+ExtendedDTraceProbes (set in CMD) enables hotspot:method__entry firing.
# binutils provides readelf, needed by the sidecar to confirm USDT availability.
FROM eclipse-temurin:17-jdk

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    maven \
    wget \
    binutils \
  && rm -rf /var/lib/apt/lists/*

# Advisory USDT check — warns if hotspot probes are absent but does not fail build.
RUN LIBJVM=$(find /usr/lib/jvm -name libjvm.so 2>/dev/null | head -1) && \
    if [ -n "$LIBJVM" ]; then \
      readelf -n "$LIBJVM" 2>/dev/null | grep -q method__entry \
        && echo "USDT probes: present (hotspot:method__entry tracing available)" \
        || echo "USDT probes: absent — eBPF will use openat fallback"; \
    else \
      echo "USDT check: libjvm.so not found at build time"; \
    fi

WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -q
COPY src ./src
RUN mvn package -q -DskipTests

EXPOSE 5002

# -XX:+ExtendedDTraceProbes enables hotspot:method__entry USDT probes at runtime.
CMD ["java", "-XX:+ExtendedDTraceProbes", "-jar", "target/app.jar"]
