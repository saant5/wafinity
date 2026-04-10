from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def same_origin(seed_url: str, candidate_url: str) -> bool:
    a = urlparse(seed_url)
    b = urlparse(candidate_url)
    return (a.scheme, a.netloc) == (b.scheme, b.netloc)

def extract_links(base_url: str, html: str):
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for a in soup.find_all("a", href=True):
        links.add(urljoin(base_url, a["href"]))
    return list(links)

def crawl(seed_url: str, seed_html: str, limit: int = 5):
    visited = []
    queue = [seed_url]

    for link in extract_links(seed_url, seed_html):
        if same_origin(seed_url, link) and link not in queue:
            queue.append(link)

    while queue and len(visited) < limit:
        u = queue.pop(0)
        if u not in visited:
            visited.append(u)

    return visited