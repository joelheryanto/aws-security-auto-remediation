# AWS Automated Security Incident Response & Auto-Remediation

Arsitektur *event-driven DevSecOps* di AWS untuk mendeteksi dan menutup celah keamanan *Security Group* (akses publik 0.0.0.0/0 atau ::/0 pada port sensitif seperti SSH, RDP, database, dan *All Traffic*) secara otomatis dalam hitungan detik.

## Arsitektur Sistem
EC2 Security Group Change -> AWS CloudTrail -> Amazon EventBridge Rule -> AWS Lambda (Python Remediation) -> Amazon SNS (Email Alert)

## Progress Implementasi
- [x] Part 1: Amazon SNS Alert Topic, AWS CloudTrail Management Trail, & IAM Least-Privilege Role
- [x] Part 2: Python Auto-Remediation Lambda, EventBridge Security Pattern, & Live Breach Simulation

## Bukti Implementasi & Pengujian Insiden
### 1. Infrastruktur Keamanan Dasar
![SNS Confirmed Subscription](screenshots/01-sns-confirmed.png)
![CloudTrail Active Logging](screenshots/02-cloudtrail-logging.png)
![IAM Least Privilege Role](screenshots/03-iam-least-privilege.png)

### 2. Deteksi EventBridge, Auto-Remediation & Email Alert
![EventBridge Security Rule Event Pattern](screenshots/04-eventbridge-event-pattern.png)
![EventBridge Security Rule Target Lambda](screenshots/04-eventbridge-target-lambda.png)
![CloudWatch Remediation Log](screenshots/05-cloudwatch-remediation-log.png)
![SNS Email Security Alert](screenshots/06-sns-email-alert.png)