# about
cloudtrail detect in native aws using lambda.

The project send sns if there is a match for certain cloudtrail API call.

The goal is to detect CloudTrail API calls that are both high-impact and indicative of malicious activity.

# workflow

![ctdr](assets/img/CTDR.drawio.png)

# deploy

here's how to:
pyyaml packaged with the lambda in the deploy directory
create s3 buckets for cloudtrail and sigma

TODO: create IAC to deploy