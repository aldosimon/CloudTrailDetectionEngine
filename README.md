# About

Detection and alert that uses cloudtrail, run in native aws using lambda.

Lambda send sns if there is a match for certain cloudtrail API call.

The goal is to detect CloudTrail API calls that are both high-impact and indicative of malicious activity by having a lambda that load from sigma signature.

## Caveat

Care must be use to choose the sigma rule that is very high-impact but not noisy. Some sigma examples are included. I also included ConsoleLogin as a test sigma.

# Workflow

![ctdr](assets/img/CTDR.drawio.png)

# Deploy
you can deploy using the provided terraform or by uploading the zipped lambda directory
## Using IAC
- prerequisite:
    - aws CLI is setup with the credentials
    - copy lambda directory to deploy/terraform/lambda -> this will be zipped and uploaded by the terraform
- terraform init
- terraform plan -> please recheck 
- terraform apply

## Uploading zip
- zip the lambda directory
- upload zip package
- set up variables:
    - correct role and permission
    - snsarn
    - bucket name for cloudtrail
    - bucket name for sigma

# Todo list 

- ~~create IAC to deploy~~
- add more sigma examples
- expand on sigma selection
- format email alert
- add threeshold feature to lambda

# References and Credits

- Sigma rules from [sigmaHQ](https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/aws/cloudtrail)