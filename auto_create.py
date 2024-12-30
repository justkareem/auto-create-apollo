import csv
import random
import re
import secrets
import pandas as pd
import time
import requests

domain_csv = pd.read_csv("cookies_data.csv")
file_headers = ["email", "team_id", "proxy_ip", "proxy_port", "proxy", "cookies", "x-csrf-token"]

# CSV file name
csv_file = "results.csv"

# Step 1: Write headers to the CSV file (only if the file doesn't exist or is empty)
try:
    with open(csv_file, mode="x", newline="") as file:  # Use "x" mode to create a new file
        writer = csv.DictWriter(file, fieldnames=file_headers)
        writer.writeheader()
except FileExistsError:
    pass  # Skip writing headers if the file already exists

def retry_request(func, retries=3, backoff_factor=2):
    for attempt in range(1, retries + 1):
        try:
            return func()
        except requests.exceptions.RequestException as e:
            print(f"Attempt {attempt} failed: {e}")
            if attempt == retries:
                raise
            sleep_time = backoff_factor ** attempt + random.uniform(0, 1)
            print(f"Retrying in {sleep_time:.2f} seconds...")
            time.sleep(sleep_time)


def create_account(email, proxy):
    """Creates an account on Apollo using the given name and domain."""
    url = "https://app.apollo.io/api/v1/users/self_serve_signup"
    headers = {
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.9",
        "content-type": "application/x-www-form-urlencoded;charset=UTF-8",
        "origin": "https://www.apollo.io",
        "priority": "u=1, i",
        "referer": "https://www.apollo.io/",
        "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    }
    data = {
        "email": email,
        "user_accepted_terms": "true",
        "trial_seat_product_id": "starter_ec_w_59",
        "pricing_variant": "24Q3_W59_V2",
        "utm_content": "buy_now",
        "utm_medium": "marketing_website",
        "utm_source": "Apollo",
        "utm_campaign": "pricing_page",
        "initial_utm_content": "buy_now",
        "initial_utm_medium": "marketing_website",
        "initial_utm_source": "Apollo",
        "initial_utm_campaign": "pricing_page",
        "initial_referrer": "https://www.apollo.io/"
    }
    # Set up proxy for the request
    proxies = {
        "http": proxy,
        "https": proxy,
    }

    try:
        def make_request():
            return requests.post(url, headers=headers, data=data, proxies=proxies, timeout=10)

        response = retry_request(make_request)
        print(f"Email: {email} - Status Code: {response.status_code}")
        print(response.text)
        team_id = response.json().get("team_id")
        return team_id
    except Exception as e:
        print(f"Error creating account: {e}")
        return None


def get_token(email, domain):
    """Verifies an Apollo account via email verification request."""
    data_row = domain_csv[domain_csv["domain"] == domain]
    url = f"https://mail.hyronleadmasters.com/SOGo/so/admin@{domain}/Mail/0/folderINBOX/view"
    headers = {
        "accept": "application/json, text/plain, */*",
        "accept-language": "en-US,en;q=0.9",
        "cookie": data_row["cookie"].item(),
        "content-type": "application/json;charset=UTF-8",
        "origin": "https://mail.hyronleadmasters.com",
        "priority": "u=1, i",
        "sec-ch-ua": '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
        "x-xsrf-token": data_row["csrf"].item()
    }

    data = {
        "sortingAttributes": {
            "sort": "arrival",
            "asc": 0
        }
    }

    try:
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            response_data = response.json()
            # Extract email headers
            email_headers = response_data.get("headers", [])[1:]

            # Initialize a list to store UIDs
            uids_from_apollo = []

            # Loop through email headers
            for sogo_email in email_headers:
                uid = sogo_email[10]  # 'uid' is at index 10

                # Check if any sender email matches 'support@tryapollo.io'
                if any(e.get("email") == "support@tryapollo.io" for e in sogo_email[4]) and any(
                        e.get("email") == email.lower() for e in sogo_email[0]):
                    uids_from_apollo.append(uid)
                for uid in uids_from_apollo:
                    response = requests.get(
                        f"https://mail.hyronleadmasters.com/SOGo/so/admin@{domain}/Mail/0/folderINBOX/{uid}/view",
                        headers=headers)
                    data = response.json()
                    # Extract the email and content
                    verification_link_match = re.search(r'token=([^&]+)', data["parts"]["content"][0]["content"])
                    if verification_link_match:
                        verification_token = verification_link_match.group(0).split("=")[1]
                        return verification_token
        else:
            print(f"Failed to verify account for {email}: {response.text}")
    except Exception as e:
        print(f"Error verifying account: {e}")


def generate_csrf_token(length=32):
    return secrets.token_hex(length // 2)  # Generate a hex string of the desired lengt


def verify_account(proxy, token, name, email):
    csrf_token = generate_csrf_token()


    headers = {
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json',
        'origin': 'https://app.apollo.io',
        'referer': 'https://app.apollo.io/',
        'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
        'x-csrf-token': csrf_token,
    }

    data = {
        "password": "6uzxgu6pgxxc",
        "name": name,
    }

    proxies = {
        "http": proxy,
        "https": proxy
    }

    verification_token_url = f"https://app.apollo.io/api/v1/password_resets/{token}"
    try:
        def make_request():
            return requests.put(verification_token_url, headers=headers, json=data, proxies=proxies)

        response = retry_request(make_request)
        print(f"Email: {email} - Status Code: {response.status_code}")
        print(response.text)
        set_cookies = response.headers.get('Set-Cookie', '')
        cookies = set_cookies.replace('\r\n', '; ') if set_cookies else ''

        # Extract csrf-token from cookies if present
        csrf_token_from_response = None
        for cookie in set_cookies.split(', '):
            if 'X-CSRF-TOKEN' in cookie:
                csrf_token_from_response = cookie.split(';')[0].split('=')[1]
                break
        headers = {
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.9",
            "content-type": "application/json",
            "cookie": cookies,
            "priority": "u=1, i",
            "referer": "https://app.apollo.io/",
            "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        }
        res = requests.get("https://app.apollo.io/api/v1/auth/check?timezone_offset=0", headers=headers,
                           proxies=proxies)
        print(res.json().get("is_logged_in"))
        print('-' * 20)
        return csrf_token_from_response, cookies
    except Exception as e:
        print(f"Error creating account: {e}")
        return None


def generate_email(used_emails, domain):
    names = pd.read_csv("names.csv")["Name"]
    while True:
        name = random.choice(names)
        email = f"{name}@{domain}"
        if email not in used_emails:
            return name, email


def main():
    proxy_csv = pd.read_csv("proxy.csv")["proxy"]
    domains = domain_csv["domain"]
    used_emails = ["Zael@hyronleadsagency.one", "Eason@hyronleadsolutions.one", "Gilberto@hyronleadsnet.com", "Charlie@hyronagency.one", "Greysen@hyronleadspro.com", "Howard@hyronleadsmarketing.one", "Primrose@hyronleadpros.one", "Josey@hyronleadspartner.com", "Anais@hyronleadnet.com", "Haziel@hyronleadboost.com", "Kaizer@hyronleadpros.com", "Khaza@hyronleadpartner.one", "Atlas@hyronleadsmarketing.com", "Levon@hyronleadnet.com", "Matheo@hyronleadsclick.com", "Mileena@hyronleads.one", "Carolyn@hyronleadservice.com", "Storm@hyronleaddigital.one", "Beaux@hyronleadsolution.com", "Craig@hyronleadconsulting.one", "Issac@hyronleadflow.one", "Jacobo@hyronleadspartners.one", "Nasir@hyronleadnetwork.one", "Karen@hyronleadsmarketing.one", "Amiyah@hyronleadspecialist.one", "Lesly@hyronleadgen.one", "Cy@hyronleadgen.one", "Trevon@hyronleaddigital.one", "Adira@hyronleadconnect.one", "Kanaan@hyronleadsmarketing.one", "Xaiden@hyronleadrise.one", "Shalom@hyronleadsgenius.com", "Eyden@hyronleadmaster.com", "Taryn@hyronleadsmarket.one", "Blakelyn@hyronleadmarketing.one", "Carolina@hyronleadsconsult.one", "Aliana@hyronleadsolutions.one", "Eithan@hyronleadmasters.one", "Denver@hyronleadhub.one", "Kashmere@hyronleadhub.one", "Jaycob@hyronleadprime.one", "Emmeline@hyronleadsmasters.com"]
    domain_usage = {domain: 0 for domain in domains}
    domain_usage["hyronleadsagency.one"] = 1
    domain_usage["hyronleadsolutions.one"] = 2
    domain_usage["hyronleadsnet.com"] = 1
    domain_usage["hyronagency.one"] = 1
    domain_usage["hyronleadspro.com"] = 1
    domain_usage["hyronleadsmarketing.one"] = 3
    domain_usage["hyronleadpros.one"] = 1
    domain_usage["hyronleadspartner.com"] = 1
    domain_usage["hyronleadnet.com"] = 2
    domain_usage["hyronleadboost.com"] = 1
    domain_usage["hyronleadpros.com"] = 1
    domain_usage["hyronleadpartner.one"] = 1
    domain_usage["hyronleadsmarketing.com"] = 1
    domain_usage["hyronleadsclick.com"] = 1
    domain_usage["hyronleadsclick.com"] = 1
    domain_usage["hyronleads.one"] = 1
    domain_usage["hyronleadservice.com"] = 1
    domain_usage["hyronleaddigital.one"] = 2
    domain_usage["hyronleadsolution.com"] = 1
    domain_usage["hyronleadconsulting.one"] = 1
    domain_usage["hyronleadflow.one"] = 1
    domain_usage["hyronleadspartners.one"] = 1
    domain_usage["hyronleadnetwork.one"] = 1
    domain_usage["hyronleadspecialist.one"] = 1
    domain_usage["hyronleadgen.one"] = 2
    domain_usage["hyronleadconnect.one"] = 1
    domain_usage["hyronleadrise.one"] = 1
    domain_usage["hyronleadsgenius.com"] = 1
    domain_usage["hyronleadmaster.com"] = 1
    domain_usage["hyronleadsmarket.one"] = 1
    domain_usage["hyronleadmarketing.one"] = 1
    domain_usage["hyronleadsconsult.one"] = 1
    domain_usage["hyronleadmasters.one"] = 1
    domain_usage["hyronleadhub.one"] = 2
    domain_usage["hyronleadprime.one"] = 1
    domain_usage["hyronleadsmasters.com"] = 1

    for proxy in proxy_csv:
        available_domains = [domain for domain, count in domain_usage.items() if count < 5]
        if not available_domains:
            print("All domains have reached the maximum account limit.")
            break
        domain = random.choice(available_domains)
        name, email = generate_email(used_emails, domain)
        used_emails.append(email)
        team_id = create_account(email, proxy)
        time.sleep(random.randint(280, 360))

        token = get_token(email, domain)
        print(token)
        csrf, cookies = verify_account(proxy, token, name, email)
        proxy_ip, proxy_port = proxy.split('@')[-1].split(':')
        row = {
            "email": email,
            "team_id": team_id,
            "proxy_ip": proxy_ip,
            "proxy_port": proxy_port,
            "proxy": proxy,
            "cookies": cookies,
            "x-csrf-token": csrf
        }
        with open(csv_file, mode="a", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=file_headers)
            writer.writerow(row)

        domain_usage[domain] += 1
        # Space out the requests randomly between 5 and 10 minutes
        sleep_time = random.randint(100, 300)
        print(f"Sleeping for {sleep_time} seconds before next account creation.")
        time.sleep(sleep_time)


if __name__ == "__main__":
    main()
