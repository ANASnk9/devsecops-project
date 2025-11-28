# Use a lightweight JDK base image
FROM eclipse-temurin:17-jdk-jammy

# Copy your JAR from Maven target folder
COPY target/*.jar app.jar

# Expose port (adjust to your app)
EXPOSE 8080

# Run the app zzddfddd
ENTRYPOINT ["java", "-jar", "app.jar"]

