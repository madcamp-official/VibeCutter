FROM eclipse-temurin:17-jdk AS build
WORKDIR /app

COPY server/gradlew .
COPY server/gradle gradle
COPY server/build.gradle server/settings.gradle ./
RUN chmod +x gradlew
COPY server/src src
RUN ./gradlew clean bootJar --no-daemon

FROM eclipse-temurin:17-jre AS runtime
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/build/libs/*.jar app.jar
COPY config /app/config
ENV CONFIG_DIR=/app/config
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
