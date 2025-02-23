FROM maven:3.9.9-eclipse-temurin-21-alpine AS build
WORKDIR /app
COPY . .
RUN mvn clean package -DskipTests

FROM openjdk:21-jdk-slim
WORKDIR /app
COPY --from=build /app/target/notes-0.0.1-SNAPSHOT.jar.jar notes.jar
EXPOSE 8080
ENTRYPOINT [ "java", "-jar", "notes.jar" ]