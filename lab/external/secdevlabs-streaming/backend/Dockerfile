# secDevLabs Streaming's API at the pinned commit (CC-LAB-0314). Lab-only,
# loopback-only. Its Maven dependencies were resolved on the host into .cache/m2 (each
# checked against its published checksum); the build is offline (`mvn -o`). Run on the
# build image's Java 11 (upstream's openjdk:8-jdk-alpine is not on Google's mirror).
FROM mirror.gcr.io/library/maven:3.6.0-jdk-11-slim@sha256:4f0face24d2f79439a8fa394555b09be99c9ad537b9b19983fb8cc358818a42d
COPY .cache/m2 /m2
COPY .cache/app/app/backend /home/app
RUN mvn -o -B -q -Dmaven.repo.local=/m2 -f /home/app/pom.xml -Dmaven.test.skip=true package \
 && cp /home/app/target/streaming-0.0.1-SNAPSHOT.jar /app.jar && rm -rf /m2 /home/app
USER nobody
EXPOSE 8080
CMD ["java", "-Xmx512m", "-Djava.security.egd=file:/dev/./urandom", "-jar", "/app.jar"]
