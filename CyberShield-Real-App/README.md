# CyberShield AI — Real Web Application

## Premium UI Upgrade
The frontend has been redesigned as a dark cinematic security SaaS dashboard with a custom CyberShield logo, security score, threat activity, quick scanners, profile, settings, and responsive layouts. The Java/Spring Boot/MySQL backend and API contracts are preserved.

A Java 25 + Spring Boot + MySQL personal security web app.

## Working features
- Signup/login with BCrypt password hashing
- Server-side session token
- Separate editable profile page
- Persistent user name/phone/alert preference in MySQL
- Suspicious message / link / payment-request analysis
- Risk score + reasons + next-step guidance
- Persistent analysis history
- Security statistics
- Responsive frontend

## Run
1. Install Java 25 and Maven.
2. Install MySQL and make sure the server is running.
3. Open `src/main/resources/application.properties` and replace `YOUR_MYSQL_PASSWORD` with your MySQL password.
4. If you already have a working local `application.properties`, keep your existing MySQL password there.
5. From this folder run:
   `mvn spring-boot:run`
6. Open `http://localhost:8080`

The `cybershield` database and tables are created/updated automatically by JPA.

## Important
This project uses a transparent rule-based scam detector for demonstration and defensive use. It is not a substitute for a bank, telecom provider, or law-enforcement verification system.
