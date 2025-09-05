# about

cloudtrail detect in native aws using lambda.

The project send sns if there is a match for certain cloudtrail API call.

The goal is to detect CloudTrail API calls that are both high-impact and indicative of malicious activity.

# workflow

![ctdr](assets/img/CTDR.drawio.png)

# deploy

here's how to:

- upload zip package (script and requirements) in the deploy directory to lambda
- set up variables:
    - correct role and permission
    - snsarn
    - bucket name for cloudtrail
    - bucket name for sigma

# todo list 

- create IAC to deploy
- format email alert