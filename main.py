from flask import Flask, render_template, request, make_response
import re
import search

app = Flask(__name__, template_folder="templates", static_folder="static")

# Regex search patterns
ipv4_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
ipv6_pattern = re.compile(r'^([\da-f]{1,4}:){7}[\da-f]{1,4}$', re.IGNORECASE)
domain_pattern = re.compile(r'^[a-zA-Z0-9]+([-.][a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$')
url_pattern = re.compile(r'^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}|(\d{1,3}\.){3}\d{1,3})(:[0-9]{1,5})?(\/.*)?$')


def quadrident_search(classic_bool, query, search_type):
    if search_type == 'domain':
        search_result = search.search_domain(classic_bool, query)
    elif search_type == 'ip':
        search_result = search.search_ip(classic_bool, query)
    elif search_type == 'url':
        search_result = search.search_url(classic_bool, query)
    else:
        search_result = search.search_hash(classic_bool, query)
    if search_result == 'http_error_exception':
            return make_response('An error code received from the server. Please try again. If the issue persists, please create an issue on GitHub or contact me for further assistance.', 400)

    if search_result == 'http_error_server':
            return make_response('An error occurred when connecting to the server. Please try again. If the issue persists, please create an issue on GitHub or contact me for further assistance.', 400)

    return render_template(search_result[0], **search_result[1])

@app.route("/")
def index():
    return render_template('index.html')


@app.route("/gui/search")
def perform_search():
    query_args = request.args
    query = query_args.get('query', '').strip() 
    classic_bool = True if query_args.get('classic') == 'true' else False

    if not query:
        return make_response("Query cannot be empty", 400)

    if re.match(domain_pattern, query):
        return quadrident_search(classic_bool, query, 'domain')
    elif re.match(ipv4_pattern, query):
        return quadrident_search(classic_bool, query, 'ip')
    elif re.match(ipv6_pattern, query):
        return quadrident_search(classic_bool, query, 'ip')
    elif re.match(url_pattern, query):
        return quadrident_search(classic_bool, query, 'url')
    else:
        return quadrident_search(classic_bool, query, 'hash')


@app.route("/api")
def api_call():
    query = request.args.get('query')

    if not query:
        return make_response("Query cannot be empty", 400)

    return search.api(query)

if __name__ == '__main__':
    app.run(port=5000, debug=True)
