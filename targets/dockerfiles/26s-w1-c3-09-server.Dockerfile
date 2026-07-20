FROM gradle:9.5.1-jdk17 AS build
WORKDIR /app

COPY server/build.gradle server/settings.gradle ./
COPY server/src src
RUN gradle clean bootJar --no-daemon

FROM eclipse-temurin:17-jre AS runtime
WORKDIR /app
COPY --from=build /app/build/libs/*.jar app.jar
COPY config /app/config
ENV CONFIG_DIR=/app/config
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
