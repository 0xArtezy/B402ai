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
from eth_account.messages import encode_defunct

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

def delay(ms: int):
    return asyncio.sleep(ms / 1000)

# ------------------------------------------
# GAS OPTIONS
# ------------------------------------------
def gas_options() -> Dict[str, Any]:
    opts = {}
    if GAS_PRICE_GWEI:
        opts["gasPrice"] = int(GAS_PRICE_GWEI) * (10 ** 9)
    if GAS_LIMIT:
        opts["gas"] = int(GAS_LIMIT)
    return opts

# ------------------------------------------
# CAPTCHA SOLVER (2CAPTCHA TURNSTILE)
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
        raise RuntimeError(f"2captcha error: {job}")

    while True:
        await asyncio.sleep(5)
        params = {
            "key": CAPTCHA_KEY,
            "action": "get",
            "id": job_id,
            "json": 1
        }
        async with session.get("http://2captcha.com/res.php", params=params) as r:
            rj = await r.json()

        if rj.get("status") == 1:
            return rj["request"]

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
        "turnstileToken": ts
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
        "turnstileToken": ts
    }
    async with session.post(f"{API_BASE}/auth/web3/verify", json=payload) as r:
        return await r.json()

# ------------------------------------------
# ERC20 APPROVE UNLIMITED
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

async def approve_unlimited():
    token_contract = aw3.eth.contract(
        address=aw3.to_checksum_address(TOKEN),
        abi=ERC20_APPROVE_ABI
    )
    max_uint = (1 << 256) - 1

    print("🟦 Approving unlimited USDT for relayer...")

    nonce = await aw3.eth.get_transaction_count(WALLET)
    tx = token_contract.functions.approve(
        RELAYER,
        max_uint
    ).build_transaction({
        "from": WALLET,
        "nonce": nonce,
        **gas_options()
    })

    signed = acct.sign_transaction(tx)
    tx_hash = await aw3.eth.send_raw_transaction(signed.rawTransaction)

    print("🔄 Approve TX:", tx_hash.hex())
    await aw3.eth.wait_for_transaction_receipt(tx_hash)

    print("🟩 Unlimited USDT approved!")

# ------------------------------------------
# PERMIT (EIP-712)
# ------------------------------------------
async def build_permit(amount: int, relayer: str):
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

    typed = {
        "types": types,
        "domain": domain,
        "primaryType": "TransferWithAuthorization",
        "message": msg,
    }

    from eth_account.messages import encode_structured_data
    signable = encode_structured_data(typed)

    signed = acct.sign_message(signable)
    sig_hex = signed.signature.hex()

    return {"authorization": msg, "signature": sig_hex}

# ------------------------------------------
# RUN CLAIM
# ------------------------------------------
async def run_claim(session: aiohttp.ClientSession, jwt: str):
    print("🔍 Fetching payment requirement...")

    url = f"{API_BASE}/faucet/drip"
    headers = {"Authorization": f"Bearer {jwt}"}

    pay = None

    async with session.post(url, json={"recipientAddress": RECIPIENT}, headers=headers) as r:
        if r.status == 402:
            data = await r.json()
            pay = data["paymentRequirements"]
            print("💰 Payment requirement:", pay["amount"])
        else:
            raise RuntimeError("❌ Cannot fetch payment requirement")

    print("🟦 Approving unlimited...")
    await approve_unlimited()

    print(f"🧱 Building {MINT_COUNT} permits...")
    permits = []
    for _ in range(MINT_COUNT):
        permits.append(await build_permit(pay["amount"], pay["relayerContract"]))

    print("\n🚀 START MINTING (will finish ALL permits)…\n")

    semaphore = asyncio.Semaphore(3)
    results = ["pending"] * len(permits)

    async def mint_one(i: int, permit: Dict[str, Any]):
        async with semaphore:
            try:
                payload = {
                    "recipientAddress": RECIPIENT,
                    "paymentPayload": {"token": TOKEN, "payload": permit},
                    "paymentRequirements": {
                        "network": pay["network"],
                        "relayerContract": pay["relayerContract"]
                    }
                }
                async with session.post(url, json=payload, headers=headers) as res:
                    if res.status in (200, 201):
                        data = await res.json()
                        print(f"🟩 Mint #{i+1} SUCCESS → {data.get('nftTransaction')}")
                        results[i] = "success"
                    else:
                        try:
                            err = await res.json()
                            msg = err.get("error") or err
                        except:
                            msg = await res.text()

                        if "already" in str(msg).lower():
                            print(f"🟡 Mint #{i+1} ALREADY CLAIMED")
                            results[i] = "success"
                        else:
                            print(f"🟥 Mint #{i+1} FAILED → {msg}")
                            results[i] = "failed"

            except Exception as e:
                print(f"🟥 Mint #{i+1} FAILED → {e}")
                results[i] = "failed"

    tasks = [asyncio.create_task(mint_one(i, permits[i])) for i in range(len(permits))]
    await asyncio.gather(*tasks)

    print("\n📊 SUMMARY:", results)

    if any(r == "success" for r in results):
        print("\n🎉 At least 1 NFT minted successfully!")
        print("🛑 All permits processed → stopping script...")
        raise SystemExit(0)
    else:
        print("\n⚠ All mints failed, script will continue waiting for next distribution.")

# ------------------------------------------
# WATCHER
# ------------------------------------------
WATCH_ADDR = [
    "0x39dcdd14a0c40e19cd8c892fd00e9e7963cd49d3".lower(),
    "0xafcd15f17d042ee3db94cdf6530a97bf32a74e02".lower(),
]

async def watch_distribution(session: aiohttp.ClientSession, jwt: str):
    print("👁 Watching for distribution...")
    last_block = 0
    running_claim = False

    while True:
        try:
            block = await aw3.eth.block_number
            if block > last_block:
                blk = await aw3.eth.get_block(block, full_transactions=True)
                txs = blk["transactions"]

                for tx in txs:
                    tx_from = tx["from"]
                    if (not running_claim) and tx_from.lower() in WATCH_ADDR:
                        print("🔥 DISTRIBUTION DETECTED")
                        running_claim = True
                        await run_claim(session, jwt)
                        running_claim = False
                        print("👁 Watching again...")

                last_block = block

        except Exception as e:
            print("⚠ Watcher error:", e)

        await asyncio.sleep(0.5)

# ------------------------------------------
# MAIN
# ------------------------------------------
async def main():
    async with aiohttp.ClientSession() as session:
        print("🔵 Solving captcha...")
        ts = await solve_turnstile(session)

        print("🔵 Getting challenge...")
        lid, challenge = await get_challenge(session, ts)

        message = challenge.get("message")
        if not message:
            raise RuntimeError("Challenge missing message field")

        signable = encode_defunct(text=message)
        signed = acct.sign_message(signable)

        verify = await verify_challenge(session, lid, signed.signature.hex(), ts)
        jwt = verify.get("jwt") or verify.get("token")

        if not jwt:
            raise RuntimeError("Login failed: no JWT/token returned")

        print("🟢 LOGIN SUCCESS!")
        await watch_distribution(session, jwt)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except SystemExit:
        pass
    except KeyboardInterrupt:
        print("Interrupted")
