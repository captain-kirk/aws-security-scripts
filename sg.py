# This script creates a CSV report of security groups attached to EC2 instances tagged "production". The report includes ingress rules.

import boto3
import json
import pprint

ec2 = boto3.client('ec2')
s3 = boto3.client('s3')

pp = pprint.PrettyPrinter(indent=4)

def get_all_instances():
  response = ec2.describe_instances(
    Filters=[
      {
        'Name': 'tag:env',
        'Values': ['production']
      }
    ]
  )
  instances = []
  for reservation in response['Reservations']:
    for instance in reservation['Instances']:
      instances.append(instance['InstanceId'])
  return instances

def get_security_groups(instances):
  sgs = []
  for instance in instances:
    response = ec2.describe_instances(
      InstanceIds=[instance]
    )
    for group in response['Reservations'][0]['Instances'][0]['SecurityGroups']:
      if group['GroupId'] not in sgs:
        sgs.append(group['GroupId'])
  return sgs

def get_ingress_rules(sg):
  response = ec2.describe_security_groups(
    GroupIds=[sg]
  )
  return response['SecurityGroups'][0]['IpPermissions']

def get_sg_name(sg):
  response = ec2.describe_security_groups(
    GroupIds=[sg]
  )
  return response['SecurityGroups'][0]['GroupName']

def main():
  report = []
  instances = get_all_instances()
  sgs = get_security_groups(instances)
  
  for sg in sgs:
    rules = get_ingress_rules(sg)
    name = get_sg_name(sg)
    report.append({
      'SecurityGroupId': sg,
      'SecurityGroupName': name,
      'IngressRules': rules
    })
  pp.pprint(report)

if __name__ == "__main__":
  main()
