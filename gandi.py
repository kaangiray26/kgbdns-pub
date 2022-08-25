import requests


class Gandi:
    def __init__(self):
        self.headers = {
            "Authorization": "Apikey <API-KEY>"
        }

    def create_subdomain(self, domain, ip="1.1.1.1"):
        data = {
            "fqdn": domain,
            "rrset_name": domain,
            "rrset_type": "A",
            "rrset_values": [ip],
            "rrset_ttl": 300
        }

        r = requests.post(
            "https://api.gandi.net/v5/livedns/domains/kgbdns.com/records", headers=self.headers, json=data)
        print(r.content, r.status_code)
        if r.status_code != 201:
            return False
        return True

    def remove_subdomain(self, domain):
        r = requests.delete(
            f"https://api.gandi.net/v5/livedns/domains/kgbdns.com/records/{domain}/A", headers=self.headers)
        if r.status_code != 204:
            return False
        return True

    def update_subdomain_ip(self, domain, ip):
        data = {
            "rrset_values": [ip],
            "rrset_ttl": 300
        }

        r = requests.put(
            f"https://api.gandi.net/v5/livedns/domains/kgbdns.com/records/{domain}/A", headers=self.headers, json=data)
        if r.status_code != 201:
            return False
        return True