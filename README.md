# Checkpoint_HEC_API
A script for Harmony Email &amp; Collaboration which utilizes the API to add or remove emails from the block-list, or quarantine them from user's mailboxes.

## Usage
- "-e", "--email_pattern", help="Email pattern to match (will be added as contains, not exact)"
- "-a", "--action", choices=["phishing", "spam", "greymail"], help="Action needed - What to classify email as"
- "-q", "--quarantine", choices=["true", "false"], default=None, help="Set 'quarantineAll' flag (true or false) -> Will quarantine emails from 7 days ago"
- "-d", "--delete", metavar="EMAIL", help="Delete an email from the blocklist by providing the email address"

## Examples
### Add email to blocklist & quarantine email 
```bash
py HEC_Blocklist_API.py -a spam -e example@test.com -q true
```

### Remove email entry from blocklist
```bash
py HEC_Blocklist_API.py -d example@test.com
```
