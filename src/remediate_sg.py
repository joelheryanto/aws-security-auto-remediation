import json
import os
import boto3

ec2_client = boto3.client('ec2')
sns_client = boto3.client('sns')

SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
SENSITIVE_PORTS = {22, 3389, 3306, 5432, 27017, 6379}


def is_sensitive_port(ip_protocol, from_port, to_port):
    if str(ip_protocol) == '-1':
        return True
    if from_port is None or to_port is None:
        return False
    return any(int(from_port) <= port <= int(to_port) for port in SENSITIVE_PORTS)


def lambda_handler(event, context):
    detail = event.get('detail', {})
    request_params = detail.get('requestParameters') or {}
    group_id = request_params.get('groupId')

    if not group_id:
        print("Event tidak memiliki groupId, melewati proses.")
        return {'statusCode': 200, 'body': 'No groupId found'}

    actor_arn = detail.get('userIdentity', {}).get('arn', 'Unknown Actor')
    aws_region = detail.get('awsRegion', 'ap-southeast-3')
    event_time = detail.get('eventTime', 'Unknown Time')

    # Ekstrak aturan dari format standar CloudTrail maupun format legacy
    raw_items = request_params.get('ipPermissions', {}).get('items', [])
    if not raw_items and 'cidrIp' in request_params:
        raw_items = [{
            'ipProtocol': request_params.get('ipProtocol', 'tcp'),
            'fromPort': request_params.get('fromPort'),
            'toPort': request_params.get('toPort'),
            'ipRanges': {'items': [{'cidrIp': request_params.get('cidrIp')}]}
        }]

    permissions_to_revoke = []
    violation_summaries = []

    for perm in raw_items:
        ip_protocol = str(perm.get('ipProtocol', 'tcp'))
        from_port = perm.get('fromPort')
        to_port = perm.get('toPort')

        if not is_sensitive_port(ip_protocol, from_port, to_port):
            continue

        ipv4_items = perm.get('ipRanges', {}).get('items', [])
        ipv6_items = perm.get('ipv6Ranges', {}).get('items', [])

        open_ipv4 = [{'CidrIp': r['cidrIp']} for r in ipv4_items if r.get('cidrIp') == '0.0.0.0/0']
        open_ipv6 = [{'CidrIpv6': r['cidrIpv6']} for r in ipv6_items if r.get('cidrIpv6') == '::/0']

        if open_ipv4 or open_ipv6:
            revoke_entry = {'IpProtocol': ip_protocol}
            if ip_protocol != '-1' and from_port is not None and to_port is not None:
                revoke_entry['FromPort'] = int(from_port)
                revoke_entry['ToPort'] = int(to_port)
            if open_ipv4:
                revoke_entry['IpRanges'] = open_ipv4
            if open_ipv6:
                revoke_entry['Ipv6Ranges'] = open_ipv6

            permissions_to_revoke.append(revoke_entry)
            port_label = 'ALL PORTS' if ip_protocol == '-1' else f"{from_port}-{to_port} ({ip_protocol.upper()})"
            cidrs = [r['CidrIp'] for r in open_ipv4] + [r['CidrIpv6'] for r in open_ipv6]
            violation_summaries.append(f"- Port: {port_label} | Source: {', '.join(cidrs)}")

    if not permissions_to_revoke:
        print(f"Aturan baru pada {group_id} aman (tidak membuka port sensitif ke publik).")
        return {'statusCode': 200, 'body': 'Compliant rule change'}

    # Auto-Remediation: cabut aturan inbound berbahaya secara otomatis
    ec2_client.revoke_security_group_ingress(
        GroupId=group_id,
        IpPermissions=permissions_to_revoke
    )
    print(f"AUTO-REMEDIATED: Berhasil mencabut aturan terbuka pada {group_id}")

    # Kirim notifikasi insiden keamanan ke Amazon SNS
    if SNS_TOPIC_ARN:
        alert_message = (
            "AWS SECURITY ALERT: INSECURE SECURITY GROUP RULE REVOKED\n\n"
            f"Status         : AUTO-REMEDIATED (Akses Publik Dicabut Otomatis)\n"
            f"Waktu Kejadian : {event_time}\n"
            f"Region         : {aws_region}\n"
            f"Security Group : {group_id}\n"
            f"Pelaku (IAM)   : {actor_arn}\n\n"
            "Detail Aturan Berbahaya yang Dicabut:\n"
            + "\n".join(violation_summaries)
            + "\n\nTindakan: Aturan inbound terbuka (0.0.0.0/0 atau ::/0) pada port sensitif "
              "telah dihapus secara otomatis oleh AWS Lambda."
        )
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"[AWS Security Alert] Open Port Auto-Revoked on {group_id}",
            Message=alert_message
        )

    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Insecure Security Group rule automatically revoked',
            'security_group_id': group_id,
            'revoked_rules': permissions_to_revoke
        })
    }