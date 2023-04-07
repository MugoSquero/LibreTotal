from django.shortcuts import render
from django.http import HttpResponse
import requests
from ast import literal_eval
import re
import random
import time
from datetime import datetime, timedelta
import base64

def x_vt_anti_abuse_header():
    rand_int = str(random.randint(10000000000, 99999999999))
    timestamp = int((datetime.now() - timedelta(days=1)).timestamp())
    concatenated_string = rand_int + '-ZG9udCBiZSBldmls-' + str(timestamp)
    encoded_string = base64.b64encode(concatenated_string.encode('utf-8'))
    return encoded_string.decode('utf-8')


def ConvertBytes(size):
    for unit in ["bytes", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024


def HTTPError():
    return HttpResponse('An error occurred. Please try again. If the issue persists, please create an issue on GitHub or contact me for further assistance.')


def searchIP(request, IPAddr):
    url = f'https://www.virustotal.com/ui/search?limit=50&relationships%5Bcomment%5D=author%2Citem&query={IPAddr}'
    
    headers = {
        'accept': 'application/json',
        'accept-encoding': 'gzip, deflate, br',
        'accept-ianguage': 'en-US,en;q=0.9,es;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json',
        'dnt': '1',
        'referer': 'https://www.virustotal.com/',
        'sec-ch-ua': '"Chromium";v="111", "Not(A:Brand";v="8"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'sec-gpc': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
        'x-app-version': 'v1x166x0',
        'x-tool': 'vt-ui-main',
        'x_vt_anti_abuse_header': x_vt_anti_abuse_header()
    }
    
    response = requests.get(url, headers=headers)
    try:
        if response.status_code == 200 and not "{'data': []," in str(response.json()):
            data = response.json()['data'][0]['attributes']
            try:
                public_key = data.get('last_https_certificate', {}).get('public_key', {})
                public_key = public_key.get(list(data.get('last_https_certificate', {}).get('public_key', {}))[0], {})
            except:
                pass
            context = {
                "regional_internet_registry": data.get('regional_internet_registry', 'No Information'),
                "jarm": data.get('jarm', 'No Information'),
                "network": data.get('network', 'No Information'),
                "last_https_certificate_date": data.get('last_https_certificate_date', 'No Information'),
                "country": data.get('country', 'No Information'),
                "as_owner": data.get('as_owner', 'No Information'),
                "asn": data.get('asn', 'No Information'),
                "continent": data.get('continent', 'No Information'),
                "whois": data.get('whois', 'No Information'),
                "reputation": data.get('reputation', 'No Information'),
                "total_votes": data.get('total_votes', {'No Information'}),
                "last_https_certificate": data.get('last_https_certificate', {'No Information'}),
                "public_key": public_key,
                "last_analysis_stats": data.get('last_analysis_stats', {'No Information'}),
                "stats_antivirus_count": sum(data.get('last_analysis_stats', {'No Information'}).get(key, 0) for key in ('malicious', 'undetected', 'suspicious', 'harmless')),
                "stats_color":  '#9b413f' if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) > 5 else ('#f2c74f' if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) >= 2 and data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) <= 5 else '#46744b'),
                "stats_text_color": "<style>.engines .circle .positives[clean]{color:#39ac4c}</style>" if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) < 5 else ("<style>.engines .circle .positives[clean]{color:#f2c74f}</style>" if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) >= 2 and data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) <= 5 else "<style>.engines .circle .positives[clean]{color:#c52420}</style>"),
                "last_analysis_results": literal_eval(str(data['last_analysis_results']).replace('category', 'Detection').replace('engine_name', 'Engine').replace('engine_version', 'Version').replace('result', 'Result').replace('method', 'Method').replace('engine_update', 'Engine Update')),
            }

            if 'classic' in request.GET.keys():
                context["css"] = 1
            else:
                context["css"] = 0

            return render(request, 'IPResults.html', context)
    except:
            return HTTPError()
    else:
        return HTTPError()


def searchDomain(request, domain):
    url = f'https://www.virustotal.com/ui/search?limit=50&relationships%5Bcomment%5D=author%2Citem&query={domain}'
    
    headers = {
        'accept': 'application/json',
        'accept-encoding': 'gzip, deflate, br',
        'accept-ianguage': 'en-US,en;q=0.9,es;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json',
        'dnt': '1',
        'referer': 'https://www.virustotal.com/',
        'sec-ch-ua': '"Chromium";v="111", "Not(A:Brand";v="8"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'sec-gpc': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
        'x-app-version': 'v1x166x0',
        'x-tool': 'vt-ui-main',
        'x_vt_anti_abuse_header': x_vt_anti_abuse_header()
    }
    
    response = requests.get(url, headers=headers)
    try:
        if response.status_code == 200 and not "{'data': []," in str(response.json()):
            data = response.json()['data'][0]['attributes']
            try:
                public_key = data.get('last_https_certificate', {}).get('public_key', {})
                public_key = public_key.get(list(data.get('last_https_certificate', {}).get('public_key', {}))[0], {})
            except:
                pass
            context = {
                "last_https_certificate_date": data.get('last_https_certificate_date', 'No Information'),
                "categories": data.get('categories', {'No Information'}),
                "last_dns_records": data.get('last_dns_records', {'No Information'}),
                "jarm": data.get('jarm', 'No Information'),
                "popularity_ranks": data.get('popularity_ranks', {'No Information'}),
                "whois": data.get('whois', 'No Information'),
                "reputation": data.get('reputation', 'No Information'),
                "total_votes": data.get('total_votes', {'No Information'}),
                "last_https_certificate": data.get('last_https_certificate', {'No Information'}),
                "public_key": public_key,
                "last_analysis_stats": data.get('last_analysis_stats', {'No Information'}),
                "stats_antivirus_count": sum(data.get('last_analysis_stats', {'No Information'}).get(key, 0) for key in ('malicious', 'undetected', 'suspicious', 'harmless')),
                "stats_color":  '#9b413f' if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) > 5 else ('#f2c74f' if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) >= 2 and data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) <= 5 else '#46744b'),
                "stats_text_color": "<style>.engines .circle .positives[clean]{color:#39ac4c}</style>" if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) < 5 else ("<style>.engines .circle .positives[clean]{color:#f2c74f}</style>" if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) >= 2 and data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) <= 5 else "<style>.engines .circle .positives[clean]{color:#c52420}</style>"),
                "last_analysis_results": literal_eval(str(data['last_analysis_results']).replace('category', 'Detection').replace('engine_name', 'Engine').replace('engine_version', 'Version').replace('result', 'Result').replace('method', 'Method').replace('engine_update', 'Engine Update')),
            }

            if 'classic' in request.GET.keys():
                context["css"] = 1
            else:
                context["css"] = 0

            return render(request, 'DomainResults.html', context)
    except:
            return HTTPError()
    else:
        return HTTPError()


def searchURL(request, domain):
    url = f'https://www.virustotal.com/ui/search?limit=50&relationships%5Bcomment%5D=author%2Citem&query={domain}'
    
    headers = {
        'accept': 'application/json',
        'accept-encoding': 'gzip, deflate, br',
        'accept-ianguage': 'en-US,en;q=0.9,es;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json',
        'dnt': '1',
        'referer': 'https://www.virustotal.com/',
        'sec-ch-ua': '"Chromium";v="111", "Not(A:Brand";v="8"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'sec-gpc': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
        'x-app-version': 'v1x166x0',
        'x-tool': 'vt-ui-main',
        'x_vt_anti_abuse_header': x_vt_anti_abuse_header()
    }
    
    response = requests.get(url, headers=headers)
    try:
        if response.status_code == 200 and not "{'data': []," in str(response.json()):
            data = response.json()['data'][0]['attributes']
            context = {
                "categories": data.get('categories', {'No Information'}),
                "trackers": data.get('trackers', {'No Information'}),
                "title": data.get('title', 'No Information'),
                "reputation": data.get('reputation', 'No Information'),
                "total_votes": data.get('total_votes', {'No Information'}),
                "outgoing_links": data.get('outgoing_links', {'No Information'}),
                "last_http_response_code": data.get('last_http_response_code', 'No Information'),
                "last_http_response_headers": data.get('last_http_response_headers', {'No Information'}),
                "last_analysis_stats": data.get('last_analysis_stats', {'No Information'}),
                "stats_antivirus_count": sum(data.get('last_analysis_stats', {'No Information'}).get(key, 0) for key in ('malicious', 'undetected', 'suspicious', 'harmless')),
                "stats_color":  '#9b413f' if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) > 5 else ('#f2c74f' if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) >= 2 and data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) <= 5 else '#46744b'),
                "stats_text_color": "<style>.engines .circle .positives[clean]{color:#39ac4c}</style>" if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) < 5 else ("<style>.engines .circle .positives[clean]{color:#f2c74f}</style>" if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) >= 2 and data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) <= 5 else "<style>.engines .circle .positives[clean]{color:#c52420}</style>"),
                "last_analysis_results": literal_eval(str(data['last_analysis_results']).replace('category', 'Detection').replace('engine_name', 'Engine').replace('engine_version', 'Version').replace('result', 'Result').replace('method', 'Method').replace('engine_update', 'Engine Update')),
            }

            if 'classic' in request.GET.keys():
                context["css"] = 1
            else:
                context["css"] = 0

            return render(request, 'URLResults.html', context)
    except:
            return HTTPError()
    else:
        return HTTPError()



def searchHash(request, hashValue):
    url = f'https://www.virustotal.com/ui/search?limit=50&relationships%5Bcomment%5D=author%2Citem&query={hashValue}'
    
    headers = {
        'accept': 'application/json',
        'accept-encoding': 'gzip, deflate, br',
        'accept-ianguage': 'en-US,en;q=0.9,es;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json',
        'dnt': '1',
        'referer': 'https://www.virustotal.com/',
        'sec-ch-ua': '"Chromium";v="111", "Not(A:Brand";v="8"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'sec-gpc': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
        'x-app-version': 'v1x166x0',
        'x-tool': 'vt-ui-main',
        'x_vt_anti_abuse_header': x_vt_anti_abuse_header()
    }
    
    response = requests.get(url, headers=headers)
    try:
        if response.status_code == 200 and not "{'data': []," in str(response.json()):
            data = response.json()['data'][0]['attributes']
            context = {
                "type_description": data.get('type_description', 'No Information'),
                "type_tags": data.get('type_tags', {'No Information'}),
                "names": data.get('names', {'No Information'}),
                "verified": data.get('signature_info', {}).get('verified', 'No Information'),
                "copyright": data.get('signature_info', {}).get('copyright', 'No Information'),
                "product": data.get('signature_info', {}).get('product', 'No Information'),
                "description": data.get('signature_info', {}).get('description', 'No Information'),
                "file_version": data.get('signature_info', {}).get('file version', 'No Information'),
                "signing_date": data.get('signature_info', {}).get('signing date', 'No Information'),
                "original_name": data.get('signature_info', {}).get('original name', 'No Information'),
                "internal_name": data.get('signature_info', {}).get('internal name', 'No Information'),
                "signers": data.get('signature_info', {}).get('signers', 'No Information'),
                "reputation": data.get('reputation', 'No Information'),
                "signers_details": data.get('signature_info', {}).get('signers details', {'No Information'}),
                "total_votes": data.get('total_votes', {'No Information'}),
                "size": ConvertBytes(data.get('size', 0)),
                "dietype": data.get('detectiteasy', {}).get('filetype', 'No Information'),
                "dievalues": data.get('detectiteasy', {}).get('values', {'No Information'}),
                "meaningful_name": data.get('meaningful_name', 'No Information'),
                "last_analysis_stats": data.get('last_analysis_stats', {'No Information'}),
                "stats_antivirus_count": sum(data.get('last_analysis_stats', {'No Information'}).get(key, 0) for key in ('malicious', 'undetected', 'suspicious', 'harmless')),
                "stats_color":  '#9b413f' if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) > 5 else ('#f2c74f' if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) >= 2 and data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) <= 5 else '#46744b'),
                "stats_text_color": "<style>.engines .circle .positives[clean]{color:#39ac4c}</style>" if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) < 5 else ("<style>.engines .circle .positives[clean]{color:#f2c74f}</style>" if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) >= 2 and data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) <= 5 else "<style>.engines .circle .positives[clean]{color:#c52420}</style>"),
                "last_analysis_results": literal_eval(str(data['last_analysis_results']).replace('category', 'Detection').replace('engine_name', 'Engine').replace('engine_version', 'Version').replace('result', 'Result').replace('method', 'Method').replace('engine_update', 'Engine Update')),
            }

            if 'classic' in request.GET.keys():
                context["css"] = 1
            else:
                context["css"] = 0

            return render(request, 'HashResults.html', context)
    except:
            return HTTPError()
    else:
        return HTTPError()


def api(request):
    apiQuery = request.GET.get("query", "")
    url = f'https://www.virustotal.com/ui/search?limit=50&relationships%5Bcomment%5D=author%2Citem&query={apiQuery}'
    
    headers = {
        'accept': 'application/json',
        'accept-encoding': 'gzip, deflate, br',
        'accept-ianguage': 'en-US,en;q=0.9,es;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json',
        'dnt': '1',
        'referer': 'https://www.virustotal.com/',
        'sec-ch-ua': '"Chromium";v="111", "Not(A:Brand";v="8"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'sec-gpc': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
        'x-app-version': 'v1x166x0',
        'x-tool': 'vt-ui-main',
        'x_vt_anti_abuse_header': x_vt_anti_abuse_header()
    }

    response = requests.get(url, headers=headers)
    return HttpResponse(response)


def PerformSearch(request):
    value = request.GET.get('query', '').strip()
    if not value:
        return HttpResponse('Query cannot be empty')
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    domain_pattern = r'^[a-zA-Z0-9]+([-.][a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$'
    url_pattern = r'^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}|(\d{1,3}\.){3}\d{1,3})(:[0-9]{1,5})?(\/.*)?$'

    if re.match(domain_pattern, value):
        return searchDomain(request, value)
    elif re.match(ip_pattern, value):
        return searchIP(request, value)
    elif re.match(url_pattern, value):
        return searchURL(request, value)
    else:
        return searchHash(request, value)



def index(request):
    return render(request, 'index.html')