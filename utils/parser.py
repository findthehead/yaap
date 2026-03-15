import yaml
from urllib.parse import urlparse

def yaml_parse(file):
    try:
        with open(file, 'r') as f:
            yam = yaml.safe_load(f)
            return yam  # can be None, {}, [], etc.
    except (FileNotFoundError, yaml.YAMLError):
        return 'Invalid YAML'
    

def text_parse(file):
    try:
        with open(file, 'r') as f:
            return f.readlines()
    except (FileNotFoundError, IOError):
        return 'Invalid File'

def markdown_parse(file):
    try:
        with open(file, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except (FileNotFoundError, IOError):
        return 'Invalid File'
    

def url_parse(host):
    parsed = urlparse(host)
    if host:
        host = parsed.netloc or parsed.path
        host = host.rstrip("/")
        return host
    else:
        return 'Invalid File'