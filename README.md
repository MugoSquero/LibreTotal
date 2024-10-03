# LibreTotal

Privacy-friendly VirusTotal frontend built with Python, Flask.

This is a privacy-friendly frontend for VirusTotal, a popular online virus scanning tool. The goal of this project is to provide a simple, user-friendly interface for searching file hashes, IP addresses, domains, and URLs for malware, while respecting users' privacy and keeping their data secure.

## Features

- Simple and intuitive user interface
- Privacy-friendly design that doesn't log user data or search queries
- Supports searching for file hashes, IP addresses, domains and URLs
- No JavaScript code, only HTML and CSS
- There is no need for a VirusTotal API key to perform a search

## Requirements

- Python 3.6 or higher
- Flask

## Installation

1. Clone this repository to your local machine using `git clone https://github.com/MugoSquero/LibreTotal`
2. Create a virtual environment and activate it using `python3 -m venv env` and then `source env/bin/activate`
3. Install the required dependencies using `pip install -r requirements.txt`
4. Run the development server using `python main.py`
5. The application should now be running at http://127.0.0.1:5000/

## Contribute

1. Fork it ( https://github.com/MugoSquero/LibreTotal/fork ).
2. Create your feature branch (`git checkout -b my-new-feature`).
3. Stage your files (`git add .`).
4. Commit your changes (`git commit -am 'Add some feature'`).
5. Push to the branch (`git push origin my-new-feature`).
6. Create a new pull request ( https://github.com/MugoSquero/LibreTotal/compare ).

## License

This project is licensed under the AGPL-3.0 License. See the `LICENSE` file for details.
