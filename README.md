# AWS Automated Security Incident Response & Auto-Remediation

Arsitektur *event-driven DevSecOps* di AWS untuk mendeteksi dan menutup celah keamanan *Security Group* (akses publik 0.0.0.0/0 pada port sensitif seperti SSH/RDP) secara otomatis dalam hitungan detik.

## Arsitektur Sistem
EC2 Security Group Change -> AWS CloudTrail -> Amazon EventBridge Rule -> AWS Lambda (Python Remediation) -> Amazon SNS (Email Alert)

## Progress Implementasi
- [x] Part 1: Amazon SNS Alert Topic, AWS CloudTrail Management Trail, & IAM Least-Privilege Role
- [ ] Part 2: Python Auto-Remediation Lambda, EventBridge Security Pattern, & Live Breach Simulation

## Bukti Infrastruktur Keamanan Dasar
![SNS Confirmed Subscription](screenshots/01-sns-confirmed.png)
![CloudTrail Active Logging](screenshots/02-cloudtrail-logging.png)
![IAM Least Privilege Role](screenshots/03-iam-least-privilege.png)