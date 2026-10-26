from urllib.parse import parse_qs, urlparse

from backend import handler as BaseHandler


class handler(BaseHandler):
    def _endpoint(self):
        return parse_qs(urlparse(self.path).query).get("endpoint", [""])[0]
