FROM gradle:8.14-jdk21 AS build

WORKDIR /workspace
COPY --chown=gradle:gradle . .
RUN gradle --no-daemon bootJar

FROM eclipse-temurin:21-jre-jammy

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /workspace/build/libs/*.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
