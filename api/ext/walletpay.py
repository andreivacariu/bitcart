import json
import urllib.parse
from collections.abc import Callable

TRON_CHAIN_IDS = {"mainnet": 728126428, "shasta": 2494104990, "nile": 3448148188}

# CAIP-2 references are the genesis hash prefixes
SOLANA_CHAIN_IDS = {
    "mainnet": "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    "devnet": "EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
    "testnet": "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z",
}

TRUST_WALLET_COIN_IDS = {
    "eip155:1": 60,
    "eip155:56": 20000714,
    "eip155:137": 966,
    "tron:728126428": 195,
    "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": 501,
}


def parse_eip681_chain_id(url: str) -> int | None:
    if not url.startswith("ethereum:"):
        return None
    _, sep, rest = url.partition("@")
    digits = ""
    for char in rest:
        if not char.isdigit():
            break
        digits += char
    return int(digits) if sep and digits else None


def get_network(coin_name: str, network: str, payment_url: str) -> str | None:
    if coin_name == "TRX":
        tron_chain_id = TRON_CHAIN_IDS.get(network)
        return f"tron:{tron_chain_id}" if tron_chain_id else None
    if coin_name == "SOL":
        solana_chain_id = SOLANA_CHAIN_IDS.get(network)
        return f"solana:{solana_chain_id}" if solana_chain_id else None
    chain_id = parse_eip681_chain_id(payment_url)
    return f"eip155:{chain_id}" if chain_id else None


def metamask_link(network: str, url: str) -> str | None:
    if not network.startswith("eip155:"):
        return None
    return f"https://link.metamask.io/dapp/{url.removeprefix('https://').removeprefix('http://')}"


def trust_wallet_link(network: str, url: str) -> str | None:
    coin_id = TRUST_WALLET_COIN_IDS.get(network)
    if coin_id is None:
        return None
    return f"https://link.trustwallet.com/open_url?coin_id={coin_id}&url={urllib.parse.quote(url, safe='')}"


def tronlink_link(network: str, url: str) -> str | None:
    if not network.startswith("tron:"):
        return None
    param = json.dumps({"url": url, "action": "open", "protocol": "TronLink", "version": "1.0"})
    return f"tronlinkoutside://pull.activity?param={urllib.parse.quote(param, safe='')}"


def solana_browse_link(base_url: str, network: str, url: str) -> str | None:
    if not network.startswith("solana:"):
        return None
    parsed = urllib.parse.urlsplit(url)
    ref = f"{parsed.scheme}://{parsed.netloc}"
    return f"{base_url}/{urllib.parse.quote(url, safe='')}?ref={urllib.parse.quote(ref, safe='')}"


def phantom_link(network: str, url: str) -> str | None:
    return solana_browse_link("https://phantom.app/ul/browse", network, url)


def solflare_link(network: str, url: str) -> str | None:
    return solana_browse_link("https://solflare.com/ul/v1/browse", network, url)


WALLET_APPS: list[tuple[str, str, Callable[[str, str], str | None]]] = [
    ("metamask", "MetaMask", metamask_link),
    ("phantom", "Phantom", phantom_link),
    ("solflare", "Solflare", solflare_link),
    ("trust", "Trust Wallet", trust_wallet_link),
    ("tronlink", "TronLink", tronlink_link),
]


def get_links(network: str | None, url: str) -> list[dict[str, str]]:
    if network is None:
        return []
    links = []
    for wallet_id, name, build_link in WALLET_APPS:
        if link := build_link(network, url):
            links.append({"id": wallet_id, "name": name, "url": link})
    return links
