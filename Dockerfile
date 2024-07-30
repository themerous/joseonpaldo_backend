# Use the official Spring Boot base image
FROM openjdk:17-jdk

# Set the working directory inside the container
WORKDIR /app

# Copy the executable jar file from the build context to the working directory
COPY build/libs/*.jar app.jar

# Copy the .env file into the container
COPY .env /app/.env

# Expose the port the application runs on
EXPOSE 8080

# Set the entry point to run the Spring Boot application
ENTRYPOINT ["java", "-jar", "app.jar"]