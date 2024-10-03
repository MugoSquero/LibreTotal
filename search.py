import requests
from ast import literal_eval
import random
import time
from datetime import datetime, timedelta
import base64
from user_agent import generate_user_agent


def x_vt_anti_abuse_header():
    rand_int = str(random.randint(10000000000, 99999999999))
    timestamp = int((datetime.now() - timedelta(days=1)).timestamp())
    concatenated_string = rand_int + '-ZG9udCBiZSBldmls-' + str(timestamp)
    encoded_string = base64.b64encode(concatenated_string.encode('utf-8'))
    return encoded_string.decode('utf-8')


def convert_bytes(size):
    for unit in ["bytes", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024


def http_error_exception():
    return 'http_error_exception'


def http_error_server():
    return 'http_error_server'


def search_ip(classic_bool, IPAddr):
    url = f'https://www.virustotal.com/ui/search?limit=50&relationships%5Bcomment%5D=author%2Citem&query={IPAddr}'
    
    headers = {
        'accept': 'application/json',
        'accept-encoding': 'gzip, deflate, br',
        'accept-ianguage': 'en-US,en;q=0.9,es;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json',
        'dnt': '1',
        'user-agent': generate_user_agent(),
        'x-app-version': 'v1x277x1',
        'x-tool': 'vt-ui-main',
        'x-vt-anti-abuse-header': x_vt_anti_abuse_header()
    }
    
    response = requests.get(url, headers=headers)
    try:
        if response.status_code == 200 and not "{'data': []," in str(response.json()):
            data = response.json()['data'][0]['attributes']
            try:
                public_key = data.get('last_https_certificate', {}).get('public_key', {'algorithm': 'unknown', 'unknown_algorithm': {'modulus': 'unknown', 'exponent': 'unknown', 'key_size': 'unknown'}})
            except:
                pass
            context = {
                "search": IPAddr,
                "regional_internet_registry": data.get('regional_internet_registry', 'No Information'),
                "jarm": data.get('jarm', 'No Information'),
                "network": data.get('network', 'No Information'),
                "last_https_certificate_date": data.get('last_https_certificate_date', 'No Information'),
                "country": data.get('country', 'No Information'),
                "as_owner": data.get('as_owner', 'No Information'),
                "asn": data.get('asn', 'No Information'),
                "continent": data.get('continent', 'No Information'),
                "whois": data.get('whois', 'No Information').replace("\n", "<br>"),
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

            if classic_bool:
                context["css"] = 1
            else:
                context["css"] = 0

            return ('IPResults.html', context)
        else:
            return http_error_exception()
    except:
        return http_error_server()


def search_domain(classic_bool, domain):
    url = f'https://www.virustotal.com/ui/search?limit=50&relationships%5Bcomment%5D=author%2Citem&query={domain}'
    
    headers = {
        'accept': 'application/json',
        'accept-encoding': 'gzip, deflate, br',
        'accept-ianguage': 'en-US,en;q=0.9,es;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json',
        'dnt': '1',
        'user-agent': generate_user_agent(),
        'x-app-version': 'v1x277x1',
        'x-tool': 'vt-ui-main',
        'x-vt-anti-abuse-header': x_vt_anti_abuse_header()
    }
    
    response = requests.get(url, headers=headers)
    try:
        if response.status_code == 200 and not "{'data': []," in str(response.json()):
            data = response.json()['data'][0]['attributes']
            public_key = data.get('last_https_certificate', {}).get('public_key', {'algorithm': 'unknown', 'unknown_algorithm': {'modulus': 'unknown', 'exponent': 'unknown', 'key_size': 'unknown'}})
            context = {
                "search": domain,
                "categories": data.get('categories', {'Category': 'No Information'}),
                "creation_date": data.get('creation_date', '0'),
                "jarm": data.get('jarm', 'No Information'),
                "last_analysis_date": data.get('last_analysis_date', '0'),
                "last_analysis_results": literal_eval(str(data['last_analysis_results']).replace('category', 'Detection').replace('engine_name', 'Engine').replace('engine_version', 'Version').replace('result', 'Result').replace('method', 'Method').replace('engine_update', 'Engine Update')),
                "last_analysis_stats": data.get('last_analysis_stats', {'unknown': 'no information'}),
                "last_dns_records": data.get('last_dns_records', [{'type': 'unknown'}, {'ttl': 'unknown'}, {'value': 'unknown'}]),
                "last_dns_records_date": data.get('last_dns_records_date', '0'),
                "last_https_certificate": data.get('last_https_certificate', {'issuer': {'C': "unknown"}, 'validity': {'not_after': 'unknown', 'not_before': 'unknown'}, 'subject': {'CN': 'unknown'}, "extensions":{"key_usage":["digitalSignature","keyEncipherment","unknown"],"extended_key_usage":["serverAuth","unknown"],"CA":"unknown","subject_key_identifier":"unknown","authority_key_identifier":{"keyid":"unknown"},"ca_information_access":{"OCSP":"http://unknown","CA Issuers":"unknown"},"subject_alternative_name":["unknown"],"certificate_policies":["unknown","unknown","unknown"],"crl_distribution_points":["http://unknown.crl","unknown"],"OID":"unknown","unknown_field":"unknown"}, 'cert_signature': {'signature_algorithm': 'unknown', 'signature': 'unknown'}}),
                "last_https_certificate_date": data.get('last_https_certificate_date', 'No Information'),
                "last_update_date": data.get('last_update_date', '0'),
                "popularity_ranks": data.get('popularity_ranks', {'Unknown Service': 'No Information'}),
                "registrar": data.get('registrar', 'Unknown Registrar'),
                "reputation": data.get('reputation', '-'),
                "tld": data.get('tld', '-'),
                "total_votes": data.get('total_votes', {"harmless": "-", "malicious": "-"}),
                "whois": data.get('whois', 'No Information').replace("\n", "<br>"),
                "whois_date": data.get('whois_date', '0'),
                "public_key": public_key,
                "stats_antivirus_count": sum(data.get('last_analysis_stats', {'No Information'}).get(key, 0) for key in ('malicious', 'undetected', 'suspicious', 'harmless')),
                "stats_color":  '#9b413f' if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) > 5 else ('#f2c74f' if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) >= 2 and data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) <= 5 else '#46744b'),
                "stats_text_color": "<style>.engines .circle .positives[clean]{color:#39ac4c}</style>" if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) < 5 else ("<style>.engines .circle .positives[clean]{color:#f2c74f}</style>" if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) >= 2 and data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) <= 5 else "<style>.engines .circle .positives[clean]{color:#c52420}</style>"),
                }

            if classic_bool:
                context["css"] = 1
            else:
                context["css"] = 0

            return ('DomainResults.html', context)
        else:
            return http_error_exception()
    except:
        return http_error_server()


def search_url(classic_bool, searchURI):
    url = f'https://www.virustotal.com/ui/search?limit=50&relationships%5Bcomment%5D=author%2Citem&query={searchURI}'
    
    headers = {
        'accept': 'application/json',
        'accept-encoding': 'gzip, deflate, br',
        'accept-ianguage': 'en-US,en;q=0.9,es;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json',
        'dnt': '1',
        'user-agent': generate_user_agent(),
        'x-app-version': 'v1x277x1',
        'x-tool': 'vt-ui-main',
        'x-vt-anti-abuse-header': x_vt_anti_abuse_header()
    }
    
    response = requests.get(url, headers=headers)
    try:
        if response.status_code == 200 and not "{'data': []," in str(response.json()):
            data = response.json()['data'][0]['attributes']
            context = {
                "search": searchURI,
                "categories": data.get('categories', {'Provider': 'No Information'}),
				"first_submission_date": data.get('first_submission_date', '0'),
				"last_analysis_date": data.get('last_analysis_date', '0'),
                "last_analysis_results": literal_eval(str(data['last_analysis_results']).replace('category', 'Detection').replace('engine_name', 'Engine').replace('engine_version', 'Version').replace('result', 'Result').replace('method', 'Method').replace('engine_update', 'Engine Update')),
                "last_analysis_stats": data.get('last_analysis_stats', {'No Information'}),
				"last_final_url": data.get('last_final_url', 'unknown'),
                "last_http_response_code": data.get('last_http_response_code', 'unknown'),
                "last_http_response_content_length": data.get('last_http_response_content_length', 'unknown'),
                "last_http_response_content_sha256": data.get('last_http_response_content_sha256', 'unknown'),
                "last_http_response_cookies": data.get('last_http_response_cookies', {'Cookie': 'No Information'}),
                "last_http_response_headers": data.get('last_http_response_headers', {'Header': 'No Information'}),
                "last_modification_date": data.get('last_modification_date', '0'),
                "last_submission_date": data.get('last_submission_date', '0'),
                "outgoing_links": data.get('outgoing_links', ["No Information"]),
                "redirection_chain": data.get('redirection_chain', ["No Information"]),
                "reputation": data.get('reputation', 'unknown'),
                "times_submitted": data.get('times_submitted', 'unknown'),
                "title": data.get('title', 'No Information'),
                "tld": data.get('tld', 'No Information'),
                "total_votes": data.get('total_votes', {'No Information'}),
                "trackers": data.get('trackers', {'No Information'}),
                "stats_antivirus_count": sum(data.get('last_analysis_stats', {'No Information'}).get(key, 0) for key in ('malicious', 'undetected', 'suspicious', 'harmless')),
                "stats_color":  '#9b413f' if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) > 5 else ('#f2c74f' if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) >= 2 and data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) <= 5 else '#46744b'),
                "stats_text_color": "<style>.engines .circle .positives[clean]{color:#39ac4c}</style>" if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) < 5 else ("<style>.engines .circle .positives[clean]{color:#f2c74f}</style>" if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) >= 2 and data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) <= 5 else "<style>.engines .circle .positives[clean]{color:#c52420}</style>"),
            }

            if classic_bool:
                context["css"] = 1
            else:
                context["css"] = 0

            return ('URLResults.html', context)
        else:
            return http_error_exception()
    except:
        return http_error_server()


def search_hash(classic_bool, hashValue):
    url = f'https://www.virustotal.com/ui/search?limit=50&relationships%5Bcomment%5D=author%2Citem&query={hashValue}'
    
    headers = {
        'accept': 'application/json',
        'accept-encoding': 'gzip, deflate, br',
        'accept-ianguage': 'en-US,en;q=0.9,es;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json',
        'dnt': '1',
        'user-agent': generate_user_agent(),
        'x-app-version': 'v1x277x1',
        'x-tool': 'vt-ui-main',
        'x-vt-anti-abuse-header': x_vt_anti_abuse_header()
    }
    
    response = requests.get(url, headers=headers)
    try:
        if response.status_code == 200 and not "{'data': []," in str(response.text):
            data = response.json()['data'][0]['attributes']
            context = {
                "search": hashValue,
                "authentihash": data.get('authentihash', 'No Information'),
                "creation_date": data.get('creation_date', 'No Information'),
                "detectiteasy": data.get("detectiteasy", {"filetype": "No Information"}),
                "detectiteasy_values": data.get("detectiteasy").get("values", {"values": [{"info": "unknown", "version": "unknown", "type": "unknown", "name": "unknown"}]}),
                "first_seen_itw_date": data.get('first_seen_itw_date', '0'),
                "first_submission_date": data.get('first_submission_date', '0'),
                "last_analysis_date": data.get('last_analysis_date', '0'),
                "last_analysis_results": literal_eval(str(data['last_analysis_results']).replace('category', 'Detection').replace('engine_name', 'Engine').replace('engine_version', 'Version').replace('result', 'Result').replace('method', 'Method').replace('engine_update', 'Engine Update')),
                "last_analysis_stats": data.get('last_analysis_stats', {'No Information'}),
                "last_modification_date": data.get('last_modification_date', '0'),
                "last_submission_date": data.get('last_submission_date', '0'),
                "magic": data.get('magic', 'No Information'),
                "md5": data.get('md5', 'No Information'),
                "meaningful_name": data.get('meaningful_name', 'No Information'),
                "names": data.get('names', ['No Information']),
                "packers": data.get('packers', {"Unknown Source": "No Information"}),
                "pe_info": data.get('pe_info', {"timestamp": "0", "imphash": "No Information", "machine_type": "No Information", "entry_point": "No Information"}), # Either a big TODO here or a complete overhaul is needed.
                "popular_threat_classification": data.get('popular_threat_classification', {"popular_threat_category": [{"value": "unknown", "count": "-"}], "suggested_threat_label": "No Information", "popular_threat_name": [{"value": "unknown", "count": "-"}]}),
                "reputation": data.get('reputation', 'No Information'),
                "sandbox_verdicts": data.get('sandbox_verdicts', {"TODO"}),
                "sha1": data.get('sha1', "No Information"),
                "sha256": data.get('sha256', "No Information"),
                "sigma_analysis_results": data.get('sigma_analysis_results', "IAMLAZY TODO"),
                "sigma_analysis_stats": data.get('sigma_analysis_stats', "IAMLAZY TODO"),
                "sigma_analysis_summary": data.get('sigma_analysis_summary', "IAMLAZY TODO"),
                "signature_info": data.get("signature_info", {"copyright": "No Information", "description": "No Information", "description": "No Information", "internal name": "No Information", "original name": "No Information", "product": "No Information"}),
                "size": convert_bytes(data.get('size', 0)),
                "ssdeep": data.get('ssdeep', 'No Information'),
                "times_submitted": data.get('times_submitted', 'No Information'),
                "tlsh": data.get('tlsh', 'No Information'),
                "total_votes": data.get('total_votes', {"harmless": "-", "malicious": "-"}),
                "trid": data.get('trid', [{"file_type": "No Information", "probability": "No Information"}]),
                "type_description": data.get('type_description', 'No Information'),
                "type_extension": data.get('type_extension', 'No Information'),
                "type_tag": data.get('type_tag', 'No Information'),
                "type_tags": data.get('type_tags', ["unknown"]),
                "unique_sources": data.get('unique_sources', 'No Information'),
                "vhash": data.get('vhash', 'No Information'),
                "zemana_behaviour": data.get('zemana_behaviour', ["No Information"]),
                "stats_antivirus_count": sum(data.get('last_analysis_stats', {'No Information'}).get(key, 0) for key in ('malicious', 'undetected', 'suspicious', 'harmless')),
                "stats_color":  '#9b413f' if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) > 5 else ('#f2c74f' if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) >= 2 and data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) <= 5 else '#46744b'),
                "stats_text_color": "<style>.engines .circle .positives[clean]{color:#39ac4c}</style>" if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) < 5 else ("<style>.engines .circle .positives[clean]{color:#f2c74f}</style>" if data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) >= 2 and data.get('last_analysis_stats', {'No Information'}).get('malicious', 0) <= 5 else "<style>.engines .circle .positives[clean]{color:#c52420}</style>"),
            }

            if classic_bool:
                context["css"] = 1
            else:
                context["css"] = 0
            return ('HashResults.html', context)
        else:
            return http_error_exception()
    except:
        return http_error_server()


def api(query):
    url = f'https://www.virustotal.com/ui/search?limit=50&relationships%5Bcomment%5D=author%2Citem&query={query}'
    
    headers = {
        'accept': 'application/json',
        'accept-encoding': 'gzip, deflate, br',
        'accept-ianguage': 'en-US,en;q=0.9,es;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json',
        'dnt': '1',
        'user-agent': generate_user_agent(),
        'x-app-version': 'v1x277x1',
        'x-tool': 'vt-ui-main',
        'x-vt-anti-abuse-header': x_vt_anti_abuse_header()
    }

    response = requests.get(url, headers=headers)
    return response.text
