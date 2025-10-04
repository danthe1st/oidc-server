FROM maven:4.0.0-rc-4-eclipse-temurin-25-alpine AS build
RUN mkdir /app
WORKDIR /app

COPY src /app/src
COPY pom.xml /app/
RUN --mount=type=cache,target=/root/.m2 mvn package -DskipTests

FROM eclipse-temurin:25-alpine

RUN addgroup -S app
RUN adduser -S app -G app
RUN mkdir /app
RUN chown app:app /app
USER app
WORKDIR /app

COPY --from=build --chown=app:app /app/target/sample-oidc-client-*.jar /app/app.jar

ENTRYPOINT [ "java", "-jar", "/app/app.jar" ]