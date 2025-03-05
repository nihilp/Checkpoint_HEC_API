import argparse
import requests
import uuid
from datetime import datetime, timedelta
import string

# Constants - Update these with your actual credentials
CLIENT_ID = ""
SECRET_KEY = ""
API_BASE_URL = "https://cloudinfra-gw.portal.checkpoint.com/app/hec-api/v1.0"
AUTH_URL = "https://cloudinfra-gw.portal.checkpoint.com/auth/external"

# Proxy settings - Update as needed
PROXY_SERVER = ""
PROXIES = {
    "http": PROXY_SERVER,
    "https": PROXY_SERVER
}

def get_access_token():
    """Fetches the API access token using Client ID and Secret Key."""
    payload = {"clientId": CLIENT_ID, "accessKey": SECRET_KEY}
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    
    try:
        response = requests.post(AUTH_URL, json=payload, headers=headers, proxies=PROXIES)
        if response.status_code == 200:
            return response.json().get("data", {}).get("token")
        print("Error: Failed to get access token.")
        return None
    except Exception:
        print("Error: Exception during authentication.")
        return None

def get_exception_id(email, token):
    """Fetches exception ID based on the sender email from the blocklist."""
    url = f"{API_BASE_URL}/exceptions/blacklist"
    headers = {
        "Authorization": f"Bearer {token}",
        "x-av-req-id": str(uuid.uuid4()),
        "Accept": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers, proxies=PROXIES)
        if response.status_code == 200:
            data = response.json().get("responseData", [])
            for item in data:
                if item.get("senderEmail") == email:
                    return item.get("entityId")
        print(f"No blocklist entry found for email '{email}'.")
        return None
    except Exception as e:
        print(f"Exception while retrieving blocklist entry: {str(e)}")
        return None

def delete_exception(email, token):
    """Deletes an email from the blocklist using its exception ID, with validation."""
    if not email.strip() or email in [".", "@", "*"] or (len(email) == 1 and email in string.printable):
        print("Error: Invalid email pattern. Cannot be empty, a single ASCII character, a single '.', '@', or '*'.")
        return False
    
    if any(c in email for c in " \t"):
        print("Error: Email pattern cannot contain spaces or tab characters.")
        return False
    
    exception_id = get_exception_id(email, token)
    if not exception_id:
        return False
    
    url = f"{API_BASE_URL}/exceptions/blacklist/delete/{exception_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "x-av-req-id": str(uuid.uuid4()),
        "Accept": "application/json"
    }
    
    try:
        response = requests.post(url, headers=headers, proxies=PROXIES)
        if response.status_code in [200, 204]:
            print(f"Successfully deleted '{email}' from the blocklist.")
            return True
        print(f"Failed to delete '{email}' - Status Code: {response.status_code}")
        return False
    except Exception as e:
        print(f"Exception during blocklist deletion: {str(e)}")
        return False
    
def get_emails_by_sender(email, token):
    """Retrieves all emails from the specified sender within the last 3 days."""
    url = f"{API_BASE_URL}/search/query"
    headers = {
        "Authorization": f"Bearer {token}",
        "x-av-req-id": str(uuid.uuid4()),
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=7) # Change this to howevever many days back you want the quarantine to pull emails from
    
    payload = {
        "requestData": {
            "entityFilter": {
                "saas": "office365_emails",
                "saasEntity": "office365_emails_email",
                "startDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "endDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.999Z")
            },
            "entityExtendedFilter": [
                {
                    "saasAttrName": "entityPayload.fromEmail",
                    "saasAttrOp": "contains",
                    "saasAttrValue": email
                }
            ]
        }
    }
    
    # print(f"Sending email search request for sender: {email}") # Debugging Output
    entity_ids = []
    while True:
        try:
            response = requests.post(url, json=payload, headers=headers, proxies=PROXIES)
            # print(f"Email search API Response: {response.status_code} - {response.text}")  # Debugging Output
            
            if response.status_code == 200:
                data = response.json()
                response_data = data.get("responseData", [])
                
                for item in response_data:
                    entity_id = item.get("entityInfo", {}).get("entityId")
                    is_quarantined = item.get("entityPayload", {}).get("isQuarantined", False)
                    
                    if entity_id and not is_quarantined:
                        entity_ids.append(entity_id)
                
                scroll_id = data.get("responseEnvelope", {}).get("scrollId")
                if not scroll_id:
                    break
                payload["requestData"]["scrollId"] = scroll_id
            else:
                print(f"Error: No emails found for sender '{email}' - Status Code: {response.status_code}")
                return []
        except Exception as e:
            print(f"Exception while retrieving emails: {str(e)}")
            return []
    
    # print(f"Retrieved entity IDs for sender '{email}': {entity_ids}")  # Debugging Output
    return entity_ids

def quarantine_emails(entity_ids, token):
    """Sends a quarantine request for a list of entity IDs and logs potential re-quarantine issues."""
    if not entity_ids:
        print("Error: No valid emails found to quarantine.")
        return False
    
    # print(f"Attempting to quarantine {len(entity_ids)} emails...") # Debugging Output
    
    url = f"{API_BASE_URL}/action/entity"
    headers = {
        "Authorization": f"Bearer {token}",
        "x-av-req-id": str(uuid.uuid4()),
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    payload = {
        "requestData": {
            "entityIds": entity_ids,
            "entityType": "office365_emails_email",
            "entityActionName": "quarantine",
            "entityActionParam": ""
        }
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers, proxies=PROXIES)
        response_json = response.json()
        
        # print(f"Quarantine API Response: {response.status_code} - {response_json}")  # Debugging Output
        
        if response.status_code == 200:
            print(f"Successfully quarantined {len(entity_ids)} emails.")
            print("If the email was previously released, it may not be re-quarantined due to HEC system restrictions.")
            return True
        print(f"Quarantine failed - Status Code: {response.status_code} - {response_json}")
        return False
    except Exception as e:
        print(f"Exception during quarantine request: {str(e)}")
        return False

def is_email_in_blocklist(email, token):
    """Checks if an email is already in the blocklist."""
    url = f"{API_BASE_URL}/exceptions/blacklist"
    headers = {
        "Authorization": f"Bearer {token}",
        "x-av-req-id": str(uuid.uuid4()),
        "Accept": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers, proxies=PROXIES)
        if response.status_code == 200:
            data = response.json().get("responseData", [])
            for item in data:
                if item.get("senderEmail") == email:
                    return True
        return False
    except Exception as e:
        print(f"Exception while checking blocklist: {str(e)}")
        return False
    
def add_to_blocklist(email_pattern, action_needed, token, quarantine_all=None):
    """Adds emails to the HEC blocklist with validation and duplicate check."""
    if not email_pattern.strip() or email_pattern in [".", "@", "*"] or (len(email_pattern) == 1 and email_pattern in string.printable):
        print("Error: Invalid email pattern. Cannot be empty, a single ASCII character, a single '.', '@', or '*'.")
        return False
    
    if any(c in email_pattern for c in " \t"):
        print("Error: Email pattern cannot contain spaces or tab characters.")
        return False
    
    if is_email_in_blocklist(email_pattern, token):
        print(f"Warning: Email '{email_pattern}' is already in the blocklist. No action taken.")
        return False
    
    url = f"{API_BASE_URL}/exceptions/blacklist"
    headers = {
        "Authorization": f"Bearer {token}",
        "x-av-req-id": str(uuid.uuid4()),
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    comment = f"CSIRT API - {action_needed.capitalize()}"
    payload = {
        "requestData": {
            "senderEmail": email_pattern,
            "senderEmailMatching": "contains",  # or "exact"
            "actionNeeded": action_needed,
            "comment": comment,
            "matchOnlyFuture": "true",
            "editedBy": ""
        }
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers, proxies=PROXIES)
        if response.status_code == 200:
            print(f"Successfully added '{email_pattern}' to blocklist with comment: '{comment}'.")
            return True
        print(f"Error: Failed to add '{email_pattern}' - Status Code: {response.status_code}")
        return False
    except Exception as e:
        print(f"Error: Exception during blocklist addition: {str(e)}")
        return False
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manage exceptions in HEC blocklist or whitelist")
    parser.add_argument("-e", "--email_pattern", help="Email pattern to match (will be added as contains, not exact)")
    parser.add_argument("-a", "--action", choices=["phishing", "spam", "greymail"], help="Action needed - What to classify email as")
    parser.add_argument("-q", "--quarantine", choices=["true", "false"], default=None, help="Set 'quarantineAll' flag (true or false) -> Will quarantine emails from 7 days ago")
    parser.add_argument("-d", "--delete", metavar="EMAIL", help="Delete an email from the blocklist by providing the email address")
    
    args = parser.parse_args()
    
    access_token = get_access_token()
    if not access_token:
        exit(1)
    
    if args.delete:
        delete_exception(args.delete, access_token)
    if args.email_pattern and args.action:
        add_to_blocklist(args.email_pattern, args.action, access_token, args.quarantine)
    if args.email_pattern and args.quarantine == "true":
        # print(f"Fetching entity IDs for sender: {args.email_pattern}") # Debugging Output
        entity_ids = get_emails_by_sender(args.email_pattern, access_token)
        # print(f"Retrieved entity IDs: {entity_ids}") # Debugging Output
        if entity_ids:
            # print("Calling quarantine_emails function") # Debugging Output
            quarantine_emails(entity_ids, access_token)

