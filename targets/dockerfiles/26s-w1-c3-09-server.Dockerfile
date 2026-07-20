FROM eclipse-temurin:17-jdk AS build
WORKDIR /app

COPY server/gradlew .
COPY server/gradle gradle
COPY server/build.gradle server/settings.gradle ./
# The student repository's wrapper uses a 10-second distribution download
# timeout.  Fresh isolated runners can legitimately take longer on first pull;
# keep the source untouched and extend only this P2 build projection.
RUN chmod +x gradlew \
    && sed -i 's/^networkTimeout=.*/networkTimeout=120000/' gradle/wrapper/gradle-wrapper.properties \
    && sed -i 's/^retries=.*/retries=3/' gradle/wrapper/gradle-wrapper.properties
COPY server/src src
RUN ./gradlew clean bootJar --no-daemon

FROM eclipse-temurin:17-jre AS runtime
WORKDIR /app
COPY --from=build /app/build/libs/*.jar app.jar
COPY config /app/config
ENV CONFIG_DIR=/app/config
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
