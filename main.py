# main_async.py
import os
import asyncio
import uuid
import time
from typing import Any, Dict, List, Optional

import aiohttp
from dotenv import load_dotenv

from web3 import AsyncWeb3
from web3.providers.async_rpc import AsyncHTTPProvider
from eth_account import Account
from eth_account.messages import encode_structured_data
from eth_typing import HexStr

load_dotenv()

# ------------------------------------------
# ENV
# ------------------------------------------
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
CAPTCHA_KEY = os.getenv("CAPTCHA_KEY")
TURNSTILE_SITEKEY = os.getenv("TURNSTILE_SITEKEY")
RPC = os.getenv("RPC")
API_BASE = os.getenv("API_BASE")
CLIENT_ID = os.getenv("CLIENT_ID")
RECIPIENT = os.getenv("RECIPIENT")
RELAYER = os.getenv("RELAYER")
TOKEN = os.getenv("TOKEN")
MINT_COUNT = int(os.getenv("MINT_COUNT", 10))
GAS_PRICE_GWEI = os.getenv("GAS_PRICE_GWEI")
GAS_LIMIT = os.getenv("GAS_LIMIT")

if not PRIVATE_KEY:
    raise RuntimeError("PRIVATE_KEY must be set in environment")

# ------------------------------------------
# PROVIDER + WALLET (async)
# ------------------------------------------
aw3 = AsyncWeb3(AsyncHTTPProvider(RPC))
acct = Account.from_key(PRIVATE_KEY)
WALLET = acct.address

def delay_ms(ms: int):
    return asyncio.sleep(ms / 1000)

# ------------------------------------------
# GAS OPTIONS HELPER
# ------------------------------------------
def gas_options() -> Dict[str, Any]:
    opts: Dict[str, Any] = {}
    if GAS_PRICE_GWEI:
        opts["gasPrice"] = int(GAS_PRICE_GWEI) * (10 ** 9)
    if GAS_LIMIT:
        opts["gas"] = int(GAS_LIMIT)
    return opts

# ------------------------------------------
# CAPTCHA SOLVER (2captcha turnstile) - async
# ------------------------------------------
async def solve_turnstile(session: aiohttp.ClientSession) -> str:
    params = {
        "key": CAPTCHA_KEY,
        "method": "turnstile",
        "sitekey": TURNSTILE_SITEKEY,
        "pageurl": "https://www.b402.ai/experience-b402",
        "json": 1,
    }
    async with session.get("http://2captcha.com/in.php", params=params) as resp:
        job = await resp.json()
    job_id = job.get("request")
    if not job_id:
        raise RuntimeError(f"2captcha in.php error: {job}")

    while True:
        await asyncio.sleep(5)
        params = {"key": CAPTCHA_KEY, "action": "get", "id": job_id, "json": 1}
        async with session.get("http://2captcha.com/res.php", params=params) as r:
            rj = await r.json()
        if rj.get("status") == 1:
            return rj.get("request")
        print(".", end="", flush=True)

# ------------------------------------------
# AUTH
# ------------------------------------------
async def get_challenge(session: aiohttp.ClientSession, ts: str):
    lid = str(uuid.uuid4())
    payload = {
        "walletType": "evm",
        "walletAddress": WALLET,
        "clientId": CLIENT_ID,
        "lid": lid,
        "turnstileToken": ts,
    }
    async with session.post(f"{API_BASE}/auth/web3/challenge", json=payload) as r:
        rj = await r.json()
    return lid, rj

async def verify_challenge(session: aiohttp.ClientSession, lid: str, sig: str, ts: str):
    payload = {
        "walletType": "evm",
        "walletAddress": WALLET,
        "clientId": CLIENT_ID,
        "lid": lid,
        "signature": sig,
        "turnstileToken": ts,
    }
    async with session.post(f"{API_BASE}/auth/web3/verify", json=payload) as r:
        return await r.json()

# ------------------------------------------
# APPROVE UNLIMITED (ERC20 approve) - async
# ------------------------------------------
ERC20_APPROVE_ABI = [
    {
        "inputs": [
            {"name": "spender", "type": "address"},
            {"name": "value", "type": "uint256"},
        ],
        "name": "approve",
        "outputs": [{"type": "bool"}],
        "stateMutability": "nonpayable",
        "type": "function",
    }
]

async def approve_unlimited() -> None:
    token_contract = aw3.eth.contract(address=aw3.to_checksum_address(TOKEN), abi=ERC20_APPROVE_ABI)
    max_uint = (1 << 256) - 1

    print("🟦 Approving unlimited USDT for relayer...")

    nonce = await aw3.eth.get_transaction_count(WALLET)
    tx = token_contract.functions.approve(RELAYER, max_uint).build_transaction({
        "from": WALLET,
        "nonce": nonce,
        **gas_options()
    })

    signed_tx = acct.sign_transaction(tx)
    tx_hash = await aw3.eth.send_raw_transaction(signed_tx.rawTransaction)
    print("🔄 Approve TX:", tx_hash.hex())

    await aw3.eth.wait_for_transaction_receipt(tx_hash)
    print("🟩 Unlimited USDT approved!")

# ------------------------------------------
# PERMIT BUILDER (EIP-712) - synchronous sign inside async
# ------------------------------------------
def build_permit_sync(amount: int, relayer: str) -> Dict[str, Any]:
    # This function just builds message and domain and signs synchronously
    now = int(time.time())
    nonce_bytes32 = aw3.keccak(text=str(uuid.uuid4())).hex()
    msg = {
        "token": TOKEN,
        "from": WALLET,
        "to": RECIPIENT,
        "value": int(amount),
        "validAfter": now - 20,
        "validBefore": now + 1800,
        "nonce": nonce_bytes32,
    }

    # Need chain id (sync call avoided here - will set chain id externally)
    return {"authorization": msg}

async def build_permit(amount: int, relayer: str) -> Dict[str, Any]:
    chain_id = await aw3.eth.chain_id
    now = int(time.time())
    nonce_bytes32 = aw3.keccak(text=str(uuid.uuid4())).hex()

    msg = {
        "token": TOKEN,
        "from": WALLET,
        "to": RECIPIENT,
        "value": int(amount),
        "validAfter": now - 20,
        "validBefore": now + 1800,
        "nonce": nonce_bytes32,
    }

    domain = {
        "name": "B402",
        "version": "1",
        "chainId": int(chain_id),
        "verifyingContract": relayer
    }

    types = {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
        ],
        "TransferWithAuthorization": [
            {"name": "token", "type": "address"},
            {"name": "from", "type": "address"},
            {"name": "to", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "validAfter", "type": "uint256"},
            {"name": "validBefore", "type": "uint256"},
            {"name": "nonce", "type": "bytes32"},
        ],
    }

    typed_data = {
        "types": types,
        "domain": domain,
        "primaryType": "TransferWithAuthorization",
        "message": msg,
    }

    signable = encode_structured_data(typed_data)
    signed = acct.sign_message(signable)
    sig_hex = signed.signature.hex()

    return {"authorization": msg, "signature": sig_hex}

# ------------------------------------------
# MAIN CLAIM FLOW
# ------------------------------------------
async def run_claim(session: aiohttp.ClientSession, jwt: str):
    print("🔍 Fetching payment requirement...")
    pay: Optional[Dict[str, Any]] = None
    url = f"{API_BASE}/faucet/drip"
    headers = {"Authorization": f"Bearer {jwt}"}

    # Try to request to find 402 payment requirement
    async with session.post(url, json={"recipientAddress": RECIPIENT}, headers=headers) as resp:
        if resp.status == 200:
            # No payment required (?) — treat as success but original JS expects 402 to get requirements
            # In JS, successful POST probably mints; here we proceed same as JS by continuing flow only if 402
            print("ℹ️ Received 200 on initial drip check (no payment requirements returned).")
        elif resp.status == 402:
            rj = await resp.json()
            pay = rj.get("paymentRequirements")
            print("💰 Payment requirement:", pay.get("amount") if pay else pay)
        else:
            text = await resp.text()
            raise RuntimeError(f"❌ Cannot fetch payment requirement: status {resp.status} - {text}")

    if not pay:
        # If pay is None but code expects it, raise to preserve original behavior
        raise RuntimeError("❌ Payment requirements not returned (expected 402).")

    print("🟦 Approving unlimited...")
    await approve_unlimited()

    print(f"🧱 Building {MINT_COUNT} permits...")
    permits: List[Dict[str, Any]] = []
    for _ in range(MINT_COUNT):
        p = await build_permit(pay["amount"], pay["relayerContract"])
        permits.append(p)

    print("\n🚀 START MINTING (will finish ALL permits)…\n")

    concurrency_limit = 3
    semaphore = asyncio.Semaphore(concurrency_limit)
    results = ["pending"] * len(permits)

    async def mint_permit(idx: int, payload: Dict[str, Any]):
        nonlocal results
        async with semaphore:
            try:
                body = {
                    "recipientAddress": RECIPIENT,
                    "paymentPayload": {"token": TOKEN, "payload": payload},
                    "paymentRequirements": {
                        "network": pay["network"],
                        "relayerContract": pay["relayerContract"]
                    }
                }
                async with session.post(url, json=body, headers=headers) as r:
                    if r.status in (200, 201):
                        resj = await r.json()
                        print(f"🟩 Mint #{idx + 1} SUCCESS → {resj.get('nftTransaction')}")
                        results[idx] = "success"
                    else:
                        # handle failure body
                        try:
                            errj = await r.json()
                            msg = errj.get("error") or errj
                        except Exception:
                            msg = await r.text()
                        lower = str(msg).lower()
                        if "already" in lower:
                            print(f"🟡 Mint #{idx + 1} ALREADY CLAIMED")
                            results[idx] = "success"
                        else:
                            print(f"🟥 Mint #{idx + 1} FAILED → {msg}")
                            results[idx] = "failed"
            except Exception as e:
                lower = str(e).lower()
                if "already" in lower:
                    print(f"🟡 Mint #{idx + 1} ALREADY CLAIMED (exception)")
                    results[idx] = "success"
                else:
                    print(f"🟥 Mint #{idx + 1} FAILED → {e}")
                    results[idx] = "failed"

    # Launch tasks
    tasks = [asyncio.create_task(mint_permit(i, permits[i])) for i in range(len(permits))]
    await asyncio.gather(*tasks)

    print("\n📊 SUMMARY:", results)

    if any(r == "success" for r in results):
        print("\n🎉 At least 1 NFT minted successfully!")
        print("🛑 All permits processed → stopping script...")
        # match original behavior to exit process
        raise SystemExit(0)
    else:
        print("\n⚠ All mints failed, script will continue waiting for next distribution.")

# ------------------------------------------
# WATCHER
# ------------------------------------------
WATCH_ADDR = set(a.lower() for a in [
    "0x39dcdd14a0c40e19cd8c892fd00e9e7963cd49d3",
    "0xafcD15f17D042eE3dB94CdF6530A97bf32A74E02"
])

async def watch_distribution(session: aiohttp.ClientSession, jwt: str):
    print("👁 Watching for distribution...")
    last_block = 0
    running_claim = False

    while True:
        try:
            block = await aw3.eth.block_number
            if block > last_block:
                blk = await aw3.eth.get_block(block, full_transactions=True)
                txs = blk.transactions if hasattr(blk, "transactions") else blk.get("transactions", [])
                for tx in txs:
                    # tx may be a dict-like or attribute object
                    tx_from = None
                    if isinstance(tx, dict):
                        tx_from = tx.get("from")
                    else:
                        # AttributeDict
                        tx_from = getattr(tx, "from", None) or getattr(tx, "sender", None) or getattr(tx, "from_address", None)
                    if not tx_from:
                        # If tx is hex or has 'from' as attribute
                        try:
                            tx_from = tx["from"]
                        except Exception:
                            continue

                    if (not running_claim) and (tx_from and tx_from.lower() in WATCH_ADDR):
                        print("🔥 DISTRIBUTION DETECTED")
                        running_claim = True
                        try:
                            await run_claim(session, jwt)
                        finally:
                            running_claim = False
                            print("👁 Watching again...")
                last_block = block
        except Exception as e:
            print("⚠ Watcher error:", str(e))
        await asyncio.sleep(0.5)

# ------------------------------------------
# MAIN BOOT (async)
# ------------------------------------------
async def main():
    async with aiohttp.ClientSession() as session:
        print("🔵 Solving captcha...")
        ts = await solve_turnstile(session)

        print("🔵 Getting challenge...")
        lid, challenge = await get_challenge(session, ts)

        # challenge expected to have .message like JS
        message = challenge.get("message") if isinstance(challenge, dict) else None
        if not message:
            raise RuntimeError("Challenge response missing 'message' field")

        # Sign the message (same as wallet.signMessage in JS)
        signed_msg = acct.sign_message(encode_structured_data({
            "types": {"EIP712Domain": [], "Message": [{"name": "message", "type": "string"}]},
            "primaryType": "Message",
            "domain": {},
            "message": {"message": message}
        })) if False else acct.sign_message(Account.sign_message.__self__ if False else Account.sign_message)  # fallback - see below

        # NOTE:
        # The JS used wallet.signMessage(challenge.message) - raw personal_sign.
        # Using eth-account: sign_message requires a SignableMessage. The easiest faithful equivalent:
        # sign using eth_account.Account.sign_message(encode_defunct(text=message), private_key)
        from eth_account.messages import encode_defunct
        signable = encode_defunct(text=message)
        signed = acct.sign_message(signable)

        verify = await verify_challenge(session, lid, signed.signature.hex(), ts)
        jwt = verify.get("jwt") or verify.get("token")
        if not jwt:
            raise RuntimeError("Login failed: jwt/token not returned from verify")

        print("🟢 LOGIN SUCCESS!")
        await watch_distribution(session, jwt)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except SystemExit as e:
        # exit gracefully preserving JS behavior
        code = int(e.code) if isinstance(e.code, int) else 0
        raise SystemExit(code)
    except KeyboardInterrupt:
        print("Interrupted by user")
