import argparse
import ipaddress
import json
import logging
import os
import ssl
from typing import Callable, Dict, List, Set, Tuple

import bs4
import elasticsearch.exceptions
import requests
import sentry_sdk
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger
from elasticsearch import Elasticsearch

ES_HOST = "elasticsearch.uksouth.bink.host"
ES_AUTH = ("ip_range_checker", "e9bdd0d1-f2f9-4afe-bb4a-c6ee638bb716")

TEAMS_URL = os.getenv(
    "TEAMS_URL",
    "https://outlook.office.com/webhook/66f08760-f657-42af-bf88-4f7e4c009af1@a6e2367a-92ea-4e5a-b565-723830bcc095/"
    "IncomingWebhook/dfbe94db45134d7e8b42f4233cd62c16/f7c46488-2054-46de-9673-e0c6e94b232c",
)

sentry_sdk.init()

logger = logging.getLogger("ip_range_checker")
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s %(name)-12s %(levelname)-8s %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


def get_ip_range(es: Elasticsearch, name: str) -> Set[str]:
    try:
        result = es.get(index="ip_range_checks", id=name)
        return set(result["_source"]["ips"])
    except elasticsearch.exceptions.NotFoundError:
        return set()


def set_ip_range(es: Elasticsearch, name: str, ips: Set[str]):
    es.index("ip_range_checks", id=name, body={"ips": sort_ips(ips)})


def sort_ips(ips: Set[str]) -> List[str]:
    # ip_network wont sort ipv4 and ipv6 in the same list
    ipv4 = sorted(
        [ip for ip in ips if ipaddress.ip_network(ip).version == 4], key=lambda item: ipaddress.ip_network(item)
    )
    ipv6 = sorted(
        [ip for ip in ips if ipaddress.ip_network(ip).version == 6], key=lambda item: ipaddress.ip_network(item)
    )

    return ipv4 + ipv6


def ip_range_diff(old_range: Set[str], new_range: Set[str]) -> Tuple[bool, str]:
    text = ""
    change = False

    new_ranges = new_range - old_range
    if new_ranges:
        change = True
        text += "<br>Additional ranges<br><pre>{0}</pre>".format("<br>".join(sort_ips(new_ranges)))

    removed_ranges = old_range - new_range
    if removed_ranges:
        change = True
        text += "<br>Removed ranges<br><pre>{0}</pre>".format("<br>".join(sort_ips(removed_ranges)))

    if change:
        text += "<br>Complete range<br><pre>{0}</pre>".format("<br>".join(sort_ips(new_range)))

    return change, text.removeprefix("<br>")


def send_to_teams(name: str, text: str):
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "d7000b",
        "summary": f"{name} IP Range change",
        "title": f"{name} IP Range change",
        "sections": [{"text": text}],
    }

    resp = requests.post(TEAMS_URL, json=payload)
    assert resp.status_code == 200


def get_azure_ip_ranges() -> Set[str]:
    page = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_0_1) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36"
    }

    resp = requests.get(page, headers=headers)
    assert resp.status_code == 200

    soup = bs4.BeautifulSoup(resp.content, features="html.parser")
    json_file = soup.find("a", attrs={"data-bi-id": "downloadretry"}).attrs["href"]

    file_resp = requests.get(json_file, headers=headers)
    data = json.loads(file_resp.content)
    frontdoor = next((section for section in data["values"] if section["id"] == "AzureFrontDoor.Frontend"))
    return set(frontdoor["properties"]["addressPrefixes"])


def get_spreedly_ip_ranges() -> Set[str]:
    page = "https://docs.spreedly.com/reference/ip-addresses/"

    resp = requests.get(page)
    assert resp.status_code == 200

    # Spreedly API ip's are not easily identified, basically the 2nd element after <h3 id="inbound-requests">
    soup = bs4.BeautifulSoup(resp.content, features="html.parser")
    h3 = soup.find("h3", attrs={"id": "inbound-requests"})

    # Pretty hacky, go through each <p> from the header, and stop at the first one that contains a <code> block
    for index, sibling in enumerate(h3.next_siblings):
        if index > 3:
            raise RuntimeError("Failed to find spreedly IPs")
        if not isinstance(sibling, bs4.Tag):
            continue
        if isinstance(sibling.next, bs4.Tag) and sibling.next.name == "code":
            break
    else:
        raise RuntimeError("Failed to find spreedly IPs")

    # Get the text from all code blocks in this <p> tag
    return {elem.text.strip() for elem in sibling.find_all("code")}


RANGES: Dict[str, Callable[[], Set[str]]] = {"Azure": get_azure_ip_ranges, "Spreedly": get_spreedly_ip_ranges}


def run():
    ssl_ctx = ssl.create_default_context(cafile="ca.pem")
    es = Elasticsearch([ES_HOST], http_auth=ES_AUTH, scheme="https", port=9200, ssl_context=ssl_ctx)

    for name, func in RANGES.items():
        logger.info(f"Processing IP Range for {name}")
        try:
            old_range = get_ip_range(es, name)
            new_range = func()

            change, text = ip_range_diff(old_range, new_range)

            if change:
                logger.info("IP Range changed")
                send_to_teams(name, text)

            set_ip_range(es, name, new_range)
        except Exception as err:
            logger.exception(f"Caught exception whilst trying to process ip range for {name}", exc_info=err)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--now", action="store_true", help="Run job now")
    args = parser.parse_args()

    if args.now:
        run()
    else:
        scheduler = BlockingScheduler()
        scheduler.add_job(run, CronTrigger("0 0 * * *"))
        scheduler.start()


if __name__ == "__main__":
    main()
