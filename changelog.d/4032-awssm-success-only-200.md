### Security
- **The AWS Secrets Manager connector accepts only HTTP 200 as success.** The AWS SDK treats every
  2xx status as success, so a 201, 202, 204 or 206 from the endpoint (a broken proxy or a
  hostile backend) with a well-formed body was returned as the secret value. `GetSecret` now
  refuses any 2xx other than 200 with an error that names only the status code. The Vault and
  Azure Key Vault connectors already required exactly 200.
