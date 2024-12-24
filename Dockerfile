FROM maven:3-openjdk-17 AS build
WORKDIR /app

COPY . .
RUN mvn clean package -DskipTests


# Run stage

FROM openjdk:17-jdk-slim
WORKDIR /app

COPY --from=build /app/target/yoga-business-management-web.war yoga-business-management-web.war
EXPOSE 8080

ENTRYPOINT ["java","-jar","yoga-business-management-web.war"]