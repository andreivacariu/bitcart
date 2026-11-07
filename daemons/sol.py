import asyncio
import base64
import contextlib
import json
import os
import time
import traceback
from collections import OrderedDict, defaultdict, deque
from contextvars import ContextVar
from dataclasses import dataclass, field
from decimal import Decimal
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

from aiohttp import ClientError as AsyncClientError
from aiohttp import ClientSession, ClientTimeout
from genericprocessor import (
    NOOP_PATH,
    PR_UNPAID,
    BlockchainFeatures,
    BlockProcessorDaemon,
    WalletDB,
    daemon_ctx,
    decimal_to_string,
    from_wei,
    get_exception_traceback,
    str_to_bool,
    to_wei,
)
from genericprocessor import Invoice as BaseInvoice
from genericprocessor import KeyStore as BaseKeyStore
from genericprocessor import Transaction as BaseTransaction
from genericprocessor import Wallet as BaseWallet
from logger import get_logger
from mnemonic import Mnemonic
from solders import compute_budget, system_program
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.token.associated import get_associated_token_address
from solders.transaction import Transaction as SolanaTransaction
from storage import Storage
from utils import AbstractRPCProvider, MultipleProviderRPC, exception_retry_middleware, get_exception_message, rpc

logger = get_logger(__name__)

daemon_ctx: ContextVar["SOLDaemon"]

with open("daemons/tokens/spl.json") as f:
    SPL_TOKENS = json.loads(f.read())

# access needs an allowlisted IP, or the access-token URLs set in SOL_SERVER
MAINNET_SERVERS = ",".join(f"http://{region}.corvus-labs.io:8899" for region in ("fra", "ams", "nyc", "lon", "tyo"))
NETWORKS = {
    "mainnet": {
        "server": MAINNET_SERVERS,
        "genesis": "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
        "tokens": SPL_TOKENS,
    },
    "devnet": {
        "server": "https://api.devnet.solana.com",
        "genesis": "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
        "tokens": {"USDC": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"},
    },
    "testnet": {
        "server": "https://api.testnet.solana.com",
        "genesis": "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY",
        "tokens": {},
    },
}

# Phantom, Solflare and Backpack derive the first account of a seed phrase at this path
SOL_ACCOUNT_PATH = "m/44'/501'/0'/0'"

TOKEN_PROGRAM_ID = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
ASSOCIATED_TOKEN_PROGRAM_ID = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
TOKEN_ACCOUNT_SIZE = 165

COMMITMENT = "confirmed"
MAX_TX_VERSION = 1  # v1 transactions are on mainnet; requesting a lower version fails with -32015
SKIPPED_SLOT_ERRORS = (-32007, -32009)
# errors of one node (unhealthy, behind, missing data or method) rather than of the request: retried on the next server
NODE_ERRORS = (-32601, -32603, -32004, -32005, -32009, -32016)
# a black-holed server costs at most RPC_RETRIES * (RPC_TIMEOUT + 1) seconds before the next one is tried
RPC_TIMEOUT = 20
RPC_CONNECT_TIMEOUT = 5
RPC_RETRIES = 3

LAMPORTS_PER_SIGNATURE = 5000
MICRO_LAMPORTS_PER_LAMPORT = 1_000_000
DEFAULT_INSTRUCTION_COMPUTE_UNITS = 200_000
MAX_COMPUTE_UNITS = 1_400_000
# limits with headroom for instructions wallets may append (e.g. Phantom's Lighthouse assertions),
# measured usage is ~450 and ~28,000 units; the priority fee is paid for the whole limit
TRANSFER_COMPUTE_UNITS = 20_000
TOKEN_TRANSFER_COMPUTE_UNITS = 60_000
PRIORITY_FEE_PERCENTILE = 75
PRIORITY_FEE_CACHE_TTL = 10.0
SLOT_CACHE_TTL = 1.0
# a payment transaction must land before its request expires. It can land until its blockhash expires,
# 150 blocks (~30 seconds with a slot every 200 ms) after it was built; the cutoff leaves a wide margin
PAYMENT_TRANSACTION_MIN_LIFETIME = 90

# getSignatureStatuses has no confirmation count for rooted transactions
FINALIZED_CONFIRMATIONS = 32
SIGNATURES_PAGE_LIMIT = 100
FETCH_CONCURRENCY = 10
PROCESSED_CACHE_SIZE = 10_000
# polls a signature may fail to fetch before it is skipped, so it doesn't hold back newer payments
MAX_FETCH_ATTEMPTS = 20

MNEMONIC = Mnemonic("english")


class SolanaRPCError(Exception):
    def __init__(self, error):
        self.code = error.get("code") if isinstance(error, dict) else None
        super().__init__(error.get("message", error) if isinstance(error, dict) else error)


def is_address(address):
    try:
        Pubkey.from_string(address)
        return True
    except (ValueError, TypeError):
        return False


def normalize_address(address):
    return str(Pubkey.from_string(address))


def get_seed_phrase(key):
    """Normalized seed phrase if the key looks like one, None otherwise"""
    key = key.strip()
    words = key.split()
    return " ".join(words) if len(words) > 1 and not key.startswith("[") else None


def load_keypair(key):
    """Load a secret key in any supported format, returns None if the key isn't a secret key"""
    key = key.strip()
    if key.startswith("["):  # solana-keygen keypair file
        try:
            return Keypair.from_bytes(bytes(json.loads(key)))
        except (ValueError, TypeError) as e:
            raise Exception("Invalid keypair") from e
    if phrase := get_seed_phrase(key):
        if not MNEMONIC.check(phrase):
            raise Exception("Invalid seed phrase")
        return Keypair.from_seed_and_derivation_path(Mnemonic.to_seed(phrase), SOL_ACCOUNT_PATH)
    try:
        return Keypair.from_base58_string(key)
    except ValueError:
        return None


def format_amount(amount, divisibility):
    value = decimal_to_string(Decimal(amount), divisibility)
    return value.rstrip("0").rstrip(".") if "." in value else value


def encode_transaction(transaction):
    return base64.b64encode(bytes(transaction)).decode()


def decode_transaction(tx):
    try:
        return SolanaTransaction.from_bytes(base64.b64decode(tx, validate=True))
    except (ValueError, TypeError) as e:
        raise Exception("Invalid transaction") from e


def calculate_fee(message):
    compute_unit_limit = None
    compute_unit_price = 0
    other_instructions = 0
    for instruction in message.instructions:
        data = bytes(instruction.data)
        if message.account_keys[instruction.program_id_index] == compute_budget.ID and data:
            if data[0] == 2:
                compute_unit_limit = int.from_bytes(data[1:5], "little")
            elif data[0] == 3:
                compute_unit_price = int.from_bytes(data[1:9], "little")
        else:
            other_instructions += 1
    if compute_unit_limit is None:
        compute_unit_limit = min(MAX_COMPUTE_UNITS, DEFAULT_INSTRUCTION_COMPUTE_UNITS * other_instructions)
    priority_fee = -(-compute_unit_price * compute_unit_limit // MICRO_LAMPORTS_PER_LAMPORT)
    return message.header.num_required_signatures * LAMPORTS_PER_SIGNATURE + priority_fee


def get_token_account(owner, mint):
    return get_associated_token_address(owner, mint, TOKEN_PROGRAM_ID)


def create_token_account_idempotent(payer, owner, mint):
    return Instruction(
        ASSOCIATED_TOKEN_PROGRAM_ID,
        bytes([1]),
        [
            AccountMeta(payer, is_signer=True, is_writable=True),
            AccountMeta(get_token_account(owner, mint), is_signer=False, is_writable=True),
            AccountMeta(owner, is_signer=False, is_writable=False),
            AccountMeta(mint, is_signer=False, is_writable=False),
            AccountMeta(system_program.ID, is_signer=False, is_writable=False),
            AccountMeta(TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
        ],
    )


def transfer_checked(source, mint, destination, owner, amount, decimals):
    return Instruction(
        TOKEN_PROGRAM_ID,
        bytes([12]) + amount.to_bytes(8, "little") + bytes([decimals]),
        [
            AccountMeta(source, is_signer=False, is_writable=True),
            AccountMeta(mint, is_signer=False, is_writable=False),
            AccountMeta(destination, is_signer=False, is_writable=True),
            AccountMeta(owner, is_signer=True, is_writable=False),
        ],
    )


def with_reference(instruction, reference):
    """Solana Pay: the reference is a read-only non-signer account of the transfer instruction"""
    accounts = [*instruction.accounts, AccountMeta(reference, is_signer=False, is_writable=False)]
    return Instruction(instruction.program_id, instruction.data, accounts)


@dataclass
class Token:
    address: str
    decimals: int
    symbol: str


@dataclass
class Transaction(BaseTransaction):
    references: frozenset = frozenset()


class ServerRejectedError(Exception):
    """The server refused the request (e.g. no access), retrying it on the same server is pointless"""


class SolanaRPCProvider(AbstractRPCProvider):
    def __init__(self, url):
        self.url = url
        self._session = None
        self.post = exception_retry_middleware(
            self.post, (AsyncClientError, TimeoutError, asyncio.TimeoutError), retries=RPC_RETRIES
        )

    @property
    def session(self):
        if self._session is None or self._session.closed:
            self._session = ClientSession(timeout=ClientTimeout(total=RPC_TIMEOUT, sock_connect=RPC_CONNECT_TIMEOUT))
        return self._session

    async def post(self, payload):
        async with self.session.post(self.url, json=payload) as response:
            if 400 <= response.status < 500 and response.status != 429:
                raise ServerRejectedError(f"Solana server refused the request with HTTP {response.status}")
            response.raise_for_status()
            return await response.json(content_type=None)

    async def send_single_request(self, method, params=None):
        """Returns the JSON-RPC response, raises only on errors of this server so that the next one is tried"""
        data = await self.post({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []})
        error = data.get("error")
        if isinstance(error, dict) and error.get("code") in NODE_ERRORS:
            raise SolanaRPCError(error)
        return data

    async def send_ping_request(self):
        data = await self.send_single_request("getHealth")
        if data.get("result") != "ok":
            raise SolanaRPCError(data.get("error", "Server is unhealthy"))
        return data

    async def close(self):
        if self._session is not None:
            await self._session.close()


class SOLFeatures(BlockchainFeatures):
    rpc: MultipleProviderRPC

    def __init__(self, rpc):
        self.rpc = rpc
        self._slot = None
        self._slot_ts = 0.0
        self._fee_rate = None
        self._fee_rate_ts = 0.0
        self._rent_exempt_minimums = {}  # changes only with the cluster's rent parameters

    async def request(self, method, *params):
        data = await self.rpc.send_request(method, list(params))
        if "error" in data:  # same answer from every server, raised after failover
            raise SolanaRPCError(data["error"])
        return data["result"]

    async def get_block_number(self):
        now = time.monotonic()
        if self._slot is not None and now - self._slot_ts < SLOT_CACHE_TTL:
            return self._slot
        self._slot = await self.request("getSlot", {"commitment": COMMITMENT})
        self._slot_ts = now
        return self._slot

    async def is_connected(self):
        try:
            return await self.request("getHealth") == "ok"
        except Exception:
            return False

    async def get_gas_price(self):  # priority fee in micro-lamports per compute unit
        now = time.monotonic()
        if self._fee_rate is not None and now - self._fee_rate_ts < PRIORITY_FEE_CACHE_TTL:
            return self._fee_rate
        fees = sorted(item["prioritizationFee"] for item in await self.request("getRecentPrioritizationFees", []))
        self._fee_rate = fees[min(len(fees) - 1, len(fees) * PRIORITY_FEE_PERCENTILE // 100)] if fees else 0
        self._fee_rate_ts = now
        return self._fee_rate

    async def get_transaction(self, tx):
        data = await self.request(
            "getTransaction",
            tx,
            {"encoding": "json", "commitment": COMMITMENT, "maxSupportedTransactionVersion": MAX_TX_VERSION},
        )
        if data is None:
            raise Exception("Transaction not found")
        return data

    get_tx_receipt = get_transaction

    async def get_confirmations(self, tx_hash, data=None) -> int:
        status = (await self.request("getSignatureStatuses", [tx_hash], {"searchTransactionHistory": True}))["value"][0]
        if status is None or status["err"] is not None:
            return 0
        if status["confirmationStatus"] == "finalized":
            return FINALIZED_CONFIRMATIONS
        return status["confirmations"] or 0

    async def get_lamports(self, address):
        return (await self.request("getBalance", address, {"commitment": COMMITMENT}))["value"]

    async def get_balance(self, address):
        return from_wei(await self.get_lamports(address))

    async def get_account_info(self, address, encoding="jsonParsed"):
        return (await self.request("getAccountInfo", address, {"encoding": encoding, "commitment": COMMITMENT}))["value"]

    async def get_token_balance(self, token_account):
        info = await self.get_account_info(token_account)
        if info is None:
            return 0
        return int(info["data"]["parsed"]["info"]["tokenAmount"]["amount"])

    async def get_rent_exempt_minimum(self, size):
        if size not in self._rent_exempt_minimums:
            self._rent_exempt_minimums[size] = await self.request("getMinimumBalanceForRentExemption", size)
        return self._rent_exempt_minimums[size]

    async def get_latest_blockhash(self):
        return Hash.from_string((await self.request("getLatestBlockhash", {"commitment": COMMITMENT}))["value"]["blockhash"])

    async def get_signatures(self, address, before=None, until=None):
        options = {"limit": SIGNATURES_PAGE_LIMIT, "commitment": COMMITMENT}
        if before is not None:
            options["before"] = before
        if until is not None:
            options["until"] = until
        return await self.request("getSignaturesForAddress", address, options)

    async def get_block(self, block, *args, **kwargs):
        if block == "latest":
            block = await self.get_block_number()
        return await self.request(
            "getBlock",
            block,
            {
                "encoding": "json",
                "commitment": COMMITMENT,
                "maxSupportedTransactionVersion": MAX_TX_VERSION,
                "transactionDetails": "full",
                "rewards": False,
            },
        )

    async def get_block_txes(self, block):
        try:
            data = await self.get_block(block)
        except SolanaRPCError as e:
            if e.code in SKIPPED_SLOT_ERRORS:
                return []
            raise
        return (data or {}).get("transactions", [])

    def is_address(self, address):
        return is_address(address)

    def normalize_address(self, address):
        return normalize_address(address)

    async def get_payment_uri(self, address, amount, divisibility, contract=None, reference=None, message=None):
        params = {}
        if amount:
            params["amount"] = format_amount(amount, divisibility)
        if contract:
            params["spl-token"] = contract.address
        if reference:
            params["reference"] = reference
        if message:
            params["message"] = message
        query = urlencode(params, quote_via=quote)
        return f"solana:{address}?{query}" if query else f"solana:{address}"

    async def process_tx_data(self, data):
        meta = data.get("meta")
        if not meta or meta["err"] is not None:
            return None
        daemon = daemon_ctx.get()
        message = data["transaction"]["message"]
        loaded = meta.get("loadedAddresses") or {}
        keys = message["accountKeys"] + loaded.get("writable", []) + loaded.get("readonly", [])
        signature = data["transaction"]["signatures"][0]
        references = frozenset(keys)
        txes = []
        sol_deltas = [post - pre for pre, post in zip(meta["preBalances"], meta["postBalances"], strict=True)]
        signers = range(message["header"]["numRequiredSignatures"])
        sol_sender = keys[min(signers, key=lambda idx: sol_deltas[idx])]
        for idx, key in enumerate(keys):
            if sol_deltas[idx] > 0 and key in daemon.addresses:
                txes.append(Transaction(signature, sol_sender, key, sol_deltas[idx], references=references))
        token_deltas = defaultdict(int)  # (owner, mint) -> change across all of owner's token accounts
        for balance in meta.get("preTokenBalances") or []:
            token_deltas[(balance.get("owner"), balance["mint"])] -= int(balance["uiTokenAmount"]["amount"])
        for balance in meta.get("postTokenBalances") or []:
            token_deltas[(balance.get("owner"), balance["mint"])] += int(balance["uiTokenAmount"]["amount"])
        for (owner, mint), delta in token_deltas.items():
            token = daemon.contracts.get(mint)
            if delta <= 0 or token is None or owner not in daemon.addresses:
                continue
            change, token_sender = min(
                ((change, sender) for (sender, sender_mint), change in token_deltas.items() if sender_mint == mint),
                key=lambda item: item[0],
            )
            if change >= 0 or token_sender is None:  # minted, or sender unknown: the fee payer pays
                token_sender = keys[0]
            txes.append(Transaction(signature, token_sender, owner, delta, mint, token.decimals, references=references))
        return txes

    def get_tx_hash(self, tx_data):
        return tx_data["transaction"]["signatures"][0]

    def get_wallet_key(self, xpub, contract=None, **extra_params):
        key = xpub
        if key and key.lstrip().startswith("["):  # keypair files are too long to be used as file names
            with contextlib.suppress(Exception):
                key = str(load_keypair(key))
        if contract:
            key += f"_{contract}"
        return key

    def current_server(self):
        return self.rpc.current_rpc.url


@dataclass
class KeyStore(BaseKeyStore):
    def load_account_from_key(self):
        keypair = load_keypair(self.key)
        if keypair is None:
            if not is_address(self.key):
                raise Exception("Error loading wallet: invalid address")
            self.address = normalize_address(self.key)
        else:
            self.seed = get_seed_phrase(self.key)
            self.address = str(keypair.pubkey())
            self.private_key = str(keypair)
        self.public_key = self.address

    def add_privkey(self, privkey):
        try:
            keypair = load_keypair(privkey)
        except Exception as e:
            raise Exception("Invalid key provided") from e
        if keypair is None:
            raise Exception("Invalid key provided")
        if str(keypair.pubkey()) != self.address:
            raise Exception("Invalid private key imported: address mismatch")
        self.private_key = str(keypair)

    @classmethod
    def load(cls, db):
        return cls(key=db.get("key", ""), contract=db.get("contract", None))

    def dump(self):
        return {"key": self.key, "contract": self.contract}


@dataclass
class Invoice(BaseInvoice):
    reference: str = None


@dataclass
class Wallet(BaseWallet):
    contract: Token = None
    token_account: str = None
    request_references: dict = field(default_factory=dict)

    def __post_init__(self):
        super().__post_init__()
        self.request_references = self.db.get_dict("request_references")

    @property
    def contract_addr(self):
        return self.contract.address if self.contract else None

    @property
    def watch_address(self):
        return self.token_account or self.address

    def set_contract(self, token):
        self.contract = token
        self.symbol = token.symbol
        self.divisibility = token.decimals
        self.token_account = str(get_token_account(Pubkey.from_string(self.address), Pubkey.from_string(token.address)))

    async def balance(self):
        if self.contract:
            return from_wei(await self.coin.get_token_balance(self.token_account), self.contract.decimals)
        return await self.coin.get_balance(self.address)

    async def create_payment_request_object(self, address, amount, message, expiration, timestamp):
        req = await super().create_payment_request_object(address, amount, message, expiration, timestamp)
        return Invoice(**{**req.to_json(), "reference": str(Keypair().pubkey())})

    def add_payment_request(self, req, save_db=True):
        if req.reference and req.status == PR_UNPAID:
            self.request_references[req.reference] = req.id
        return super().add_payment_request(req, save_db=save_db)

    def remove_from_detection_dict(self, req):
        super().remove_from_detection_dict(req)
        if req.reference:
            self.request_references.pop(req.reference, None)

    def set_request_address(self, key, address):
        req = self.get_request(key)
        if not req:
            return None
        self.request_addresses.pop(req.payment_address, None)  # keep the reference registered
        req.payment_address = address
        self.request_addresses[address] = req.id
        self.add_payment_request(req)
        return req

    def clear_requests(self):
        self.request_references.clear()
        super().clear_requests()

    def find_request_id(self, tx):
        for reference in tx.references:
            if reference in self.request_references:
                return self.request_references[reference]
        return self.request_addresses.get(tx.from_addr)

    async def export_request(self, req):
        data = await super().export_request(req)
        data["reference"] = req.reference
        data["URI"] = await self.coin.get_payment_uri(
            req.address, req.amount, self.divisibility, contract=self.contract, reference=req.reference, message=req.message
        )
        return data


class SOLDaemon(BlockProcessorDaemon):
    name = "SOL"
    BASE_SPEC_FILE = "daemons/spec/eth.json"
    DEFAULT_PORT = 5012

    DIVISIBILITY = 9
    BLOCK_TIME = 3  # seconds between polls of watched accounts
    DEFAULT_MAX_SYNC_BLOCKS = 18000  # (60/0.2)=300*60 (a slot every 200 ms), sizes the rescan_blocks history

    UNIT = "lamports"

    KEYSTORE_CLASS = KeyStore
    WALLET_CLASS = Wallet
    INVOICE_CLASS = Invoice

    def __init__(self):
        super().__init__()
        self.TOKENS = NETWORKS[self.NET]["tokens"]
        self.token_symbols = {mint: symbol for symbol, mint in self.TOKENS.items()}
        self.contracts = {}
        # plain copies: stored dicts are bound to the config db and can't be put back into it
        self.cursors = {account: dict(cursor) for account, cursor in self.config.get("account_cursors", {}).items()}
        self.processed_signatures = OrderedDict()
        self.fetch_failures = {}

    def load_env(self):
        super().load_env()
        if not any(self.SERVER):  # an empty SOL_SERVER (e.g. passed through by docker compose) means the default
            self.SERVER = self.get_default_server_url().split(",")
        self.MAX_SYNC_SECONDS = self.env("MAX_SYNC_HOURS", cast=int, default=1) * 60 * 60

    def get_default_server_url(self):
        if self.NET not in NETWORKS:
            raise ValueError(f"Invalid network passed: {self.NET}. Valid choices are {', '.join(NETWORKS)}.")
        return NETWORKS[self.NET]["server"]

    async def update_server(self, start_new=True):
        if not self.SERVER.strip():
            self.SERVER = self.get_default_server_url()
        await super().update_server(start_new=start_new)

    async def check_network(self, providers):
        """Refuse servers of another cluster: invoices, tokens and the checkout's chain all follow SOL_NETWORK"""
        expected = NETWORKS[self.NET]["genesis"]
        checked = 0
        for idx, provider in enumerate(providers):
            try:
                genesis = (await provider.send_single_request("getGenesisHash"))["result"]
            except Exception as e:
                logger.warning(f"Could not check the network of Solana server #{idx + 1}: {get_exception_message(e)}")
                continue
            if genesis != expected:
                raise ValueError(
                    f"Solana server #{idx + 1} is not on {self.NET} (genesis hash {genesis}): check SOL_SERVER and SOL_NETWORK"
                )
            checked += 1
        if not checked:
            raise ValueError("No Solana server responded, could not check that they are on the configured network")

    async def create_coin(self, archive=False):
        providers = [SolanaRPCProvider(server) for server in self.SERVER]
        try:
            await self.check_network(providers)
        except Exception:
            for provider in providers:
                await provider.close()
            raise
        multi_provider = MultipleProviderRPC(providers)
        await multi_provider.start()
        self.coin = SOLFeatures(multi_provider)

    async def shutdown_coin(self, final=False, archive_only=False):
        if not hasattr(self, "coin"):
            return
        await self.coin.rpc.stop()
        for provider in self.coin.rpc.providers:
            await provider.close()

    async def get_token(self, address):
        try:
            mint = normalize_address(address)
        except (ValueError, TypeError) as e:
            raise Exception("Invalid token mint") from e
        if mint in self.contracts:
            return self.contracts[mint]
        symbol = self.token_symbols.get(mint)
        if symbol is None:
            raise Exception(f"Unsupported token, supported ones: {', '.join(self.TOKENS) or 'none'}")
        info = await self.coin.get_account_info(mint)
        if info is None or info["owner"] != str(TOKEN_PROGRAM_ID) or info["data"]["parsed"]["type"] != "mint":
            raise Exception("Invalid token mint")
        self.contracts[mint] = Token(mint, info["data"]["parsed"]["info"]["decimals"], symbol)
        return self.contracts[mint]

    async def load_wallet(self, xpub, contract, diskless=False, extra_params=None):
        if extra_params is None:
            extra_params = {}
        wallet_key = self.coin.get_wallet_key(xpub, contract, **extra_params)
        if wallet_key in self.wallets:
            return self.wallets[wallet_key]
        if not xpub:
            return None
        token = await self.get_token(contract) if contract else None
        if diskless:
            wallet = self.restore_wallet_from_text(xpub, contract, path=NOOP_PATH, **extra_params)
        else:
            wallet_path = os.path.join(self.get_wallet_path(), wallet_key)
            if not os.path.exists(wallet_path):
                self.restore(xpub, wallet_path=wallet_path, contract=contract, **extra_params)
            storage = Storage(wallet_path)
            wallet = self.WALLET_CLASS(self.coin, WalletDB(storage.read()), storage)
        if token:
            wallet.set_contract(token)
        if wallet.watch_address not in self.cursors:
            # like the first start of a block processing wallet: only transactions from now on are processed
            self.cursors[wallet.watch_address] = {"signature": None, "slot": await self.coin.get_block_number()}
            self.save_cursors()
        self.wallets[wallet_key] = wallet
        self.wallets_updates[wallet_key] = deque(maxlen=self.POLLING_CAP)
        self.addresses[wallet.address].add(wallet_key)
        await wallet.start(self.latest_blocks.copy())
        return wallet

    def save_cursors(self):
        self.config.set_config("account_cursors", self.cursors)

    async def process_pending(self):
        while self.running:
            try:
                slot = await self.coin.get_block_number()
                if await self.poll_watched_accounts():
                    self.save_cursors()
                if slot != self.latest_height:
                    self.latest_height = slot
                    await self.trigger_event({"event": "new_block", "height": slot}, None)
                self.synchronized = True  # set it once, as we just need to ensure initial sync was done
            except Exception:
                logger.error("Error processing watched accounts:")
                logger.error(traceback.format_exc())
            await asyncio.sleep(self.BLOCK_TIME)

    async def poll_watched_accounts(self):
        accounts = list({wallet.watch_address for wallet in list(self.wallets.values())})
        semaphore = asyncio.Semaphore(FETCH_CONCURRENCY)
        results = await asyncio.gather(
            *(self.poll_account(account, semaphore) for account in accounts), return_exceptions=True
        )
        for account, result in zip(accounts, results, strict=True):
            if isinstance(result, Exception):
                logger.error(f"Error polling {account}:\n{get_exception_traceback(result)}")
        return any(result is True for result in results)

    async def fetch_new_signatures(self, account, cursor, semaphore):
        cutoff = time.time() - self.MAX_SYNC_SECONDS
        new = []
        before = None
        while True:
            async with semaphore:
                page = await self.coin.get_signatures(account, before=before, until=cursor["signature"])
            for item in page:
                if (
                    item["signature"] == cursor["signature"]
                    or item["slot"] < cursor["slot"]
                    or (item.get("blockTime") or cutoff) < cutoff
                ):
                    return new[::-1]
                new.append(item)
            if len(page) < SIGNATURES_PAGE_LIMIT:
                return new[::-1]
            before = page[-1]["signature"]

    async def fetch_transaction(self, signature, semaphore):
        async with semaphore:
            return await self.coin.get_transaction(signature)

    def fetch_failed(self, signature, error):
        """Whether to keep retrying a transaction that failed to fetch"""
        attempts = self.fetch_failures.get(signature, 0) + 1
        if attempts < MAX_FETCH_ATTEMPTS:
            self.fetch_failures[signature] = attempts
            logger.debug(f"Error fetching transaction {signature}, retrying on the next poll: {error}")
            return True
        self.fetch_failures.pop(signature, None)
        logger.error(f"Skipping transaction {signature}, it failed to fetch {attempts} times: {error}")
        return False

    async def process_signature(self, signature, data):
        self.processed_signatures[signature] = None
        while len(self.processed_signatures) > PROCESSED_CACHE_SIZE:
            self.processed_signatures.popitem(last=False)
        try:
            for tx in await self.coin.parse_transactions(data):
                await self.process_transaction(tx)
        except Exception:
            logger.error(f"Error processing transaction {signature}:")
            logger.error(traceback.format_exc())

    async def poll_account(self, account, semaphore):
        cursor = self.cursors.get(account)
        if cursor is None:  # its wallet was closed after the poll started
            return False
        items = await self.fetch_new_signatures(account, cursor, semaphore)
        signatures = [
            item["signature"] for item in items if item["err"] is None and item["signature"] not in self.processed_signatures
        ]
        fetched = await asyncio.gather(*(self.fetch_transaction(sig, semaphore) for sig in signatures), return_exceptions=True)
        transactions = dict(zip(signatures, fetched, strict=True))
        cursor_moved = False
        retrying = False  # the cursor stays before a transaction that will be fetched again, newer ones still count
        for item in items:
            signature = item["signature"]
            data = transactions.get(signature)
            if isinstance(data, Exception):
                if self.fetch_failed(signature, data):
                    retrying = True
                    continue
            elif data is not None and signature not in self.processed_signatures:
                self.fetch_failures.pop(signature, None)
                await self.process_signature(signature, data)
            if not retrying and account in self.cursors:
                self.cursors[account] = {"signature": signature, "slot": item["slot"]}
                cursor_moved = True
        return cursor_moved

    async def close_wallet_impl(self, key, locked=False):
        wallet = self.wallets.get(key)
        closed = await super().close_wallet_impl(key, locked=locked)
        if closed and wallet.watch_address not in {other.watch_address for other in list(self.wallets.values())}:
            # throwaway wallets (payouts, seed generation) would otherwise keep their cursors forever
            self.cursors.pop(wallet.watch_address, None)
            self.save_cursors()
        return closed

    async def process_transaction(self, tx):
        if tx.divisibility is None:
            tx.divisibility = self.DIVISIBILITY
        if tx.to not in self.addresses:
            return
        amount = from_wei(tx.value, tx.divisibility)
        for wallet_key in list(self.addresses[tx.to]):
            wallet = self.wallets.get(wallet_key)
            if wallet is None or tx.contract != wallet.contract_addr:  # closed while an event was being sent
                continue
            await self.trigger_event(
                {
                    "event": "new_transaction",
                    "tx": tx.hash,
                    "from_address": tx.from_addr,
                    "to": tx.to,
                    "amount": decimal_to_string(amount, tx.divisibility),
                    "contract": tx.contract,
                },
                wallet_key,
            )
            request_id = wallet.find_request_id(tx)
            if request_id is not None:
                self.loop.create_task(wallet.process_new_payment(request_id, tx, amount, wallet_key))

    async def build_transaction(self, payer, instructions, compute_units, feerate=None, multiplier=None):
        compute_unit_price = int(Decimal(feerate)) if feerate is not None else await self.getfeerate(multiplier=multiplier)
        message = Message.new_with_blockhash(
            [
                compute_budget.set_compute_unit_limit(compute_units),
                compute_budget.set_compute_unit_price(compute_unit_price),
                *instructions,
            ],
            payer,
            await self.coin.get_latest_blockhash(),
        )
        return SolanaTransaction.new_unsigned(message)

    async def simulate(self, transaction, sig_verify):
        result = (
            await self.coin.request(
                "simulateTransaction",
                encode_transaction(transaction),
                {"encoding": "base64", "commitment": COMMITMENT, "sigVerify": sig_verify},
            )
        )["value"]
        if result["err"] is not None:
            logs = result.get("logs") or []
            raise Exception(f"Transaction simulation failed: {result['err']}" + (f" ({logs[-1]})" if logs else ""))

    async def check_destination(self, destination, lamports):
        info = await self.coin.get_account_info(str(destination), encoding="base64")
        if info is not None:
            if info["owner"] == str(TOKEN_PROGRAM_ID):
                raise Exception("Destination is a token account, use the wallet address instead")
            return
        minimum = await self.coin.get_rent_exempt_minimum(0)
        if 0 < lamports < minimum:
            raise Exception(
                f"Amount is below the {format_amount(from_wei(minimum), self.DIVISIBILITY)} SOL minimum for a new account"
            )

    #########
    # Methods
    #########

    @rpc(requires_network=True)
    async def add_peer(self, url, wallet=None):
        raise NotImplementedError("Solana RPC providers do not allow to add peers")

    @rpc(requires_network=True)
    async def broadcast(self, tx, wallet=None):
        transaction = decode_transaction(tx)
        await self.simulate(transaction, sig_verify=True)
        # preflight already done by the simulation above, some providers reject preflight
        return await self.coin.request(
            "sendTransaction",
            encode_transaction(transaction),
            {"encoding": "base64", "skipPreflight": True, "preflightCommitment": COMMITMENT},
        )

    @rpc(requires_network=True)
    async def get_default_fee(self, tx, wallet=None):
        message = decode_transaction(tx).message
        fee = calculate_fee(message)
        for instruction in message.instructions:  # payouts may create the recipient's token account
            if message.account_keys[instruction.program_id_index] == ASSOCIATED_TOKEN_PROGRAM_ID:
                token_account = message.account_keys[instruction.accounts[1]]
                if await self.coin.get_account_info(str(token_account), encoding="base64") is None:
                    fee += await self.coin.get_rent_exempt_minimum(TOKEN_ACCOUNT_SIZE)
        return self.coin.to_dict(from_wei(fee))

    @rpc(requires_wallet=True, requires_network=True)
    async def get_payment_transaction(self, key, account, amount=None, wallet=None):
        """Unsigned transaction paying the request from account

        amount is the full amount shown to the customer, it may exceed the request's amount which is reduced
        by the store's underpaid tolerance
        """
        wallet_obj = self.wallets[wallet]
        req = wallet_obj.get_request(key)
        if req is None:
            raise Exception("Request not found")
        if req.status != PR_UNPAID:
            raise Exception("Request is not payable")
        if req.exp and req.time + req.exp - time.time() < PAYMENT_TRANSACTION_MIN_LIFETIME:
            raise Exception("Request is not payable: it expires before a transaction could land")
        due = max(Decimal(amount), req.amount) if amount is not None else req.amount
        if not due:
            raise Exception("Request is not payable: it has no amount")
        lamports = to_wei(due - req.sent_amount, wallet_obj.divisibility)
        if lamports <= 0:
            raise Exception("Request is not payable")
        if not is_address(account):
            raise Exception("Invalid address")
        payer = Pubkey.from_string(account)
        merchant = Pubkey.from_string(wallet_obj.address)
        reference = Pubkey.from_string(req.reference)
        native_balance = await self.coin.get_lamports(account)
        instructions = []
        rent = 0
        if wallet_obj.contract:
            mint = Pubkey.from_string(wallet_obj.contract.address)
            balance = await self.coin.get_token_balance(str(get_token_account(payer, mint)))
            if await self.coin.get_account_info(wallet_obj.token_account, encoding="base64") is None:
                instructions.append(create_token_account_idempotent(payer, merchant, mint))
                rent = await self.coin.get_rent_exempt_minimum(TOKEN_ACCOUNT_SIZE)
            transfer = transfer_checked(
                get_token_account(payer, mint),
                mint,
                get_token_account(merchant, mint),
                payer,
                lamports,
                wallet_obj.divisibility,
            )
            instructions.append(with_reference(transfer, reference))
            compute_units = TOKEN_TRANSFER_COMPUTE_UNITS
            required_native = 0
        else:
            if lamports < await self.coin.get_rent_exempt_minimum(0) and await self.coin.get_lamports(str(merchant)) == 0:
                raise Exception("Request is not payable: the amount is below the minimum for a new account")
            balance = native_balance
            transfer = system_program.transfer(
                system_program.TransferParams(from_pubkey=payer, to_pubkey=merchant, lamports=lamports)
            )
            instructions.append(with_reference(transfer, reference))
            compute_units = TRANSFER_COMPUTE_UNITS
            required_native = lamports
        transaction = await self.build_transaction(payer, instructions, compute_units)
        fee = calculate_fee(transaction.message) + rent
        # the payer's account must stay rent-exempt or be emptied, anything in between fails
        rent_exempt_minimum = await self.coin.get_rent_exempt_minimum(0)
        if 0 < native_balance - required_native - fee < rent_exempt_minimum:
            fee += rent_exempt_minimum
        if balance >= lamports and native_balance >= required_native + fee:
            await self.simulate(transaction, sig_verify=False)
        return {
            "transaction": encode_transaction(transaction),
            "decimals": wallet_obj.divisibility,
            "amount": str(lamports),
            "balance": str(balance),
            "fee": str(fee),
            "native_balance": str(native_balance),
        }

    @rpc
    def get_tokens(self, wallet=None):
        return self.TOKENS

    @rpc
    def get_tx_hash(self, tx_data, wallet=None):
        return str(decode_transaction(tx_data).signatures[0])

    @rpc
    def get_tx_size(self, tx_data, wallet=None):
        return len(bytes(decode_transaction(tx_data)))

    @rpc(requires_network=True)
    async def get_used_fee(self, tx_hash, wallet=None):
        return self.coin.to_dict(from_wei((await self.coin.get_transaction(tx_hash))["meta"]["fee"]))

    @rpc(requires_network=True)
    async def getaddressbalance_contract(self, address, contract, wallet=None):
        token = await self.get_token(contract)
        balance = await self.coin.get_token_balance(
            str(get_token_account(Pubkey.from_string(normalize_address(address)), Pubkey.from_string(token.address)))
        )
        return {
            "balance": decimal_to_string(from_wei(balance, token.decimals), token.decimals),
            "divisibility": token.decimals,
        }

    @rpc(requires_network=True)
    async def gettransaction(self, tx, wallet=None):
        data = self.coin.to_dict(await self.coin.get_transaction(tx))
        data["confirmations"] = await self.coin.get_confirmations(tx)
        return data

    @rpc(requires_wallet=True)
    async def listaddresses(self, unused=False, funded=False, balance=False, wallet=None):
        unused, funded, balance = str_to_bool(unused), str_to_bool(funded), str_to_bool(balance)
        address = self.wallets[wallet].address
        addr_balance = await self.coin.get_balance(address)
        if (unused and (addr_balance > 0)) or (funded and addr_balance == 0):
            return []
        if balance:
            return [(address, self.coin.to_dict(addr_balance))]
        return [address]

    @rpc
    def make_seed(self, nbits=128, language="english", full_info=False, wallet=None):
        seed = Mnemonic(language).generate(nbits)
        if not full_info:
            return seed
        keystore = self.KEYSTORE_CLASS(key=seed)
        return {
            "seed": seed,
            "private_key": keystore.private_key,
            "address": keystore.address,
        }

    @rpc
    async def modifypaymenturl(self, url, amount, divisibility=None, wallet=None):
        if not Decimal(amount):
            return url
        parsed = urlparse(url)
        query = dict(parse_qsl(parsed.query))
        query["amount"] = format_amount(amount, divisibility if divisibility is not None else self.DIVISIBILITY)
        return urlunparse(parsed._replace(query=urlencode(query, quote_via=quote)))

    @rpc(requires_network=True)
    async def payto(self, destination, amount, fee=None, feerate=None, gas=None, unsigned=False, wallet=None, *args, **kwargs):
        source = kwargs["src_address"] if "src_address" in kwargs else self.wallets[wallet].address
        if not is_address(destination):
            raise Exception("Invalid address")
        lamports = to_wei(Decimal(amount), self.DIVISIBILITY)
        if lamports < 0:
            raise Exception("Out of bounds amount")
        destination = Pubkey.from_string(destination)
        if str(destination) != source:
            await self.check_destination(destination, lamports)
        transfer = system_program.transfer(
            system_program.TransferParams(from_pubkey=Pubkey.from_string(source), to_pubkey=destination, lamports=lamports)
        )
        # payout send-all estimates the fee and builds the transfer with the same gas_price to spend the balance exactly
        feerate = feerate if feerate is not None else kwargs.get("gas_price")
        transaction = await self.build_transaction(
            Pubkey.from_string(source), [transfer], TRANSFER_COMPUTE_UNITS, feerate, kwargs.get("speed_multiplier")
        )
        if unsigned:
            return encode_transaction(transaction)
        private_key = kwargs["private_key"] if "private_key" in kwargs else self.wallets[wallet].keystore.private_key
        return self._sign_transaction(encode_transaction(transaction), private_key)

    @rpc(requires_network=True)
    async def readcontract(self, address, function, *args, wallet=None):
        token = await self.get_token(address)
        if function == "decimals":
            return token.decimals
        if function == "symbol":
            return token.symbol
        if function == "balanceOf" and len(args) == 1:
            if not is_address(args[0]):
                raise Exception("Invalid arguments for balanceOf function")
            owner = Pubkey.from_string(args[0])
            return await self.coin.get_token_balance(str(get_token_account(owner, Pubkey.from_string(token.address))))
        raise Exception(f"Contract ABI is missing {function} function")

    @rpc(requires_wallet=True)
    def signmessage(self, address=None, message=None, wallet=None):
        if self.wallets[wallet].is_watching_only():
            raise Exception("This is a watching-only wallet")
        # Mimic electrum API
        if not address and not message:
            raise ValueError("No message specified")
        if not message:
            message = address
        keypair = Keypair.from_base58_string(self.wallets[wallet].keystore.private_key)
        return str(keypair.sign_message(message.encode("utf-8")))

    def _sign_transaction(self, tx, private_key):
        if private_key is None:
            raise Exception("This is a watching-only wallet")
        try:
            keypair = load_keypair(private_key)
        except Exception as e:
            raise Exception("Invalid key provided") from e
        if keypair is None:
            raise Exception("Invalid key provided")
        transaction = decode_transaction(tx)
        message = transaction.message
        if keypair.pubkey() not in message.account_keys[: message.header.num_required_signatures]:
            raise Exception("Private key is not a signer of this transaction")
        transaction.partial_sign([keypair], message.recent_blockhash)
        return encode_transaction(transaction)

    @rpc(requires_wallet=True, requires_network=True)
    async def transfer(self, address, to, value, unsigned=False, feerate=None, speed_multiplier=None, wallet=None):
        token = await self.get_token(address)
        if not is_address(to):
            raise Exception("Invalid address")
        try:
            amount = to_wei(Decimal(value), token.decimals)
        except Exception as e:
            raise Exception("Invalid arguments for transfer function") from e
        if amount < 0:
            raise Exception("Out of bounds amount")
        owner = Pubkey.from_string(self.wallets[wallet].address)
        destination = Pubkey.from_string(to)
        mint = Pubkey.from_string(token.address)
        transfer = transfer_checked(
            get_token_account(owner, mint), mint, get_token_account(destination, mint), owner, amount, token.decimals
        )
        if destination == owner:  # used to estimate the network fee of invoices, the account rent isn't part of it
            instructions = [transfer]
        else:
            await self.check_destination(destination, 0)
            instructions = [create_token_account_idempotent(owner, destination, mint), transfer]
        transaction = await self.build_transaction(
            owner, instructions, TOKEN_TRANSFER_COMPUTE_UNITS, feerate, speed_multiplier
        )
        if unsigned:
            return encode_transaction(transaction)
        signed = self._sign_transaction(encode_transaction(transaction), self.wallets[wallet].keystore.private_key)
        return await self.broadcast(signed)

    @rpc
    async def validatecontract(self, address, wallet=None):
        try:
            await self.get_token(address)
            return True
        except Exception:
            return False

    @rpc
    def verifymessage(self, address, signature, message, wallet=None):
        try:
            return Signature.from_string(signature).verify(Pubkey.from_string(address), message.encode("utf-8"))
        except ValueError:
            return False


if __name__ == "__main__":
    daemon = SOLDaemon()
    daemon.start()
