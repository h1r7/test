import os
import asyncio
import logging
import json
import random
import string
import hmac
import hashlib
from datetime import datetime, date, timedelta
import time
from typing import Optional, List, Dict, Any, Set, Tuple
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from itsdangerous import URLSafeTimedSerializer
from urllib.parse import quote
import discord
from discord import app_commands
from discord.ext import commands, tasks
from discord.ui import View, Modal, TextInput, Button
from dotenv import load_dotenv
from user_agents import parse
import aiohttp
from aiohttp import web
import aiosqlite
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_FILE = os.path.join(BASE_DIR, "users.db")
CONFIG_FILE = os.path.join(BASE_DIR, "sync_config.json")
LOG_FILE = os.path.join(BASE_DIR, "verify_bot.log")
SERIAL_FILE = os.path.join(BASE_DIR, "sync_serial.json")

BOT_TOKEN = os.getenv("BOT_TOKEN")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
CLIENT_ID = os.getenv("CLIENT_ID")
INTERNAL_API_SECRET = os.getenv("INTERNAL_API_SECRET")
ENCRYPTION_SALT_STR = os.getenv("ENCRYPTION_SALT")
WEBHOOK_PORT = int(os.getenv("WEBHOOK_PORT", 9090))
ADMIN_LOG_CHANNEL_ID_STR = os.getenv("ADMIN_LOG_CHANNEL_ID")
ADMIN_CONTROL_CHANNEL_ID_STR = os.getenv("ADMIN_CONTROL_CHANNEL_ID")
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
WEBHOOK_ENCRYPTION_KEY_STR = os.getenv("WEBHOOK_ENCRYPTION_KEY")
WEBHOOK_AUTH_SECRET = os.getenv("WEBHOOK_AUTH_SECRET")

RETRY_DELAY_SECONDS = 1.5 # 재시도 전 대기 시간 (초)
API_CALL_DELAY_SECONDS = 0.1 # 각 API 호출 전 기본 지연 시간
USERS_TO_PROCESS_PER_RUN = 10
MAX_API_ATTEMPTS = 3
webhook_server_running = False

CONFIG_LOCK = asyncio.Lock() # 설정 파일 접근을 위한 전역 Lock
SERIAL_LOCK = asyncio.Lock()

REDIRECT_URI = "https://dicotm20.com/verify"

if not all([BOT_TOKEN, CLIENT_SECRET, CLIENT_ID, INTERNAL_API_SECRET, ENCRYPTION_SALT_STR, FLASK_SECRET_KEY, WEBHOOK_ENCRYPTION_KEY_STR, WEBHOOK_AUTH_SECRET]): # <-- WEBHOOK_AUTH_SECRET 추가
    raise ValueError("필수 환경 변수(...) 로드 실패.")

try:
    ENCRYPTION_SALT = base64.urlsafe_b64decode(ENCRYPTION_SALT_STR)
    if len(ENCRYPTION_SALT) < 16:
        logging.warning("ENCRYPTION_SALT 길이가 너무 짧습니다 (16바이트 이상 권장).")
except (TypeError, ValueError, base64.binascii.Error) as e:
    logging.warning(f"ENCRYPTION_SALT Base64 디코딩 실패 ({e}). UTF-8 인코딩으로 사용합니다. Base64 인코딩된 Salt 사용을 권장합니다.")
    ENCRYPTION_SALT = ENCRYPTION_SALT_STR.encode('utf-8')

def _derive_key(password: str, salt: bytes) -> bytes:
    if not password or not salt:
        raise ValueError("키 파생을 위한 password 또는 salt가 비어있습니다.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key

try:
    DB_DERIVED_KEY = _derive_key(INTERNAL_API_SECRET, ENCRYPTION_SALT)
    db_fernet = Fernet(DB_DERIVED_KEY)
    logging.info("Database encryption/decryption Fernet object initialized successfully.")
except ValueError as e:
    logging.critical(f"DB 암호화 키 파생 실패: {e}", exc_info=True)
    raise SystemExit(f"DB 암호화 키 파생 실패: {e}")
except Exception as e:
     logging.critical(f"DB Fernet 객체 초기화 실패: {e}", exc_info=True)
     raise SystemExit(f"DB Fernet 객체 초기화 실패: {e}")

try:
    WEBHOOK_DERIVED_KEY = _derive_key(WEBHOOK_ENCRYPTION_KEY_STR, ENCRYPTION_SALT)
    webhook_fernet = Fernet(WEBHOOK_DERIVED_KEY)
    logging.info("Webhook data decryption Fernet object initialized successfully.")
except ValueError as e:
    logging.critical(f"웹훅 암호화 키 파생 실패: {e}", exc_info=True)
    raise SystemExit(f"웹훅 암호화 키 파생 실패: {e}")
except Exception as e:
    logging.critical(f"웹훅 Fernet 객체 초기화 실패: {e}", exc_info=True)
    raise SystemExit(f"웹훅 Fernet 객체 초기화 실패: {e}")

try:
    serializer = URLSafeTimedSerializer(FLASK_SECRET_KEY)
    logging.info("URLSafeTimedSerializer initialized successfully for state signing.")
except Exception as e:
    logging.critical(f"Failed to initialize URLSafeTimedSerializer: {e}", exc_info=True)
    raise SystemExit("Failed to initialize state serializer.")

def encrypt_data(data: str) -> Optional[str]:
    if not data: return None
    try:
        encrypted_bytes = db_fernet.encrypt(data.encode('utf-8'))
        return base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')
    except Exception as e:
        logging.error(f"DB 데이터 암호화 실패: {e}", exc_info=True)
        return None

def decrypt_data(encrypted_data_str: Optional[str]) -> Optional[str]:
    if not encrypted_data_str: return None
    try:
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data_str.encode('utf-8'))
        decrypted_bytes = db_fernet.decrypt(encrypted_bytes)
        return decrypted_bytes.decode('utf-8')
    except InvalidToken:
        logging.warning(f"DB 데이터 복호화 실패 (Invalid Token): 키 변경 또는 데이터 손상 가능성.")
        return None
    except Exception as e:
        logging.error(f"DB 데이터 복호화 중 오류: {e}", exc_info=True)
        return None

def decrypt_webhook_data(encrypted_data_b64_str: Optional[str]) -> Optional[dict]:
    if not encrypted_data_b64_str:
        logging.warning("decrypt_webhook_data: 암호화된 데이터가 없습니다.")
        return None
    try:
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data_b64_str.encode('utf-8'))
        decrypted_json_bytes = webhook_fernet.decrypt(encrypted_bytes)
        decrypted_dict = json.loads(decrypted_json_bytes.decode('utf-8'))
        return decrypted_dict
    except InvalidToken:
        logging.error("웹훅 데이터 복호화 실패 (Invalid Token): 키가 잘못되었거나 데이터가 손상/변조되었을 수 있습니다.")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"복호화된 웹훅 데이터 JSON 파싱 실패: {e}")
        return None
    except Exception as e:
        logging.error(f"웹훅 데이터 복호화 중 예상치 못한 오류: {e}", exc_info=True)
        return None

ADMIN_LOG_CHANNEL_ID: Optional[int] = None
if ADMIN_LOG_CHANNEL_ID_STR:
    try:
        ADMIN_LOG_CHANNEL_ID = int(ADMIN_LOG_CHANNEL_ID_STR)
    except ValueError:
        logging.error("ADMIN_LOG_CHANNEL_ID 환경 변수가 유효한 숫자 ID가 아닙니다.")
        # You might want to raise an error or handle this case appropriately
        # raise ValueError("ADMIN_LOG_CHANNEL_ID must be a valid integer.")
else:
    logging.warning("ADMIN_LOG_CHANNEL_ID 환경 변수가 설정되지 않았습니다. 자동 토큰 검사 로그가 전송되지 않습니다.")

ADMIN_CONTROL_CHANNEL_ID: Optional[int] = None
if ADMIN_CONTROL_CHANNEL_ID_STR:
    try:
        ADMIN_CONTROL_CHANNEL_ID = int(ADMIN_CONTROL_CHANNEL_ID_STR)
    except ValueError:
        logging.error("ADMIN_CONTROL_CHANNEL_ID 환경 변수가 유효한 숫자 ID가 아닙니다.")
else:
    logging.warning("ADMIN_CONTROL_CHANNEL_ID 환경 변수가 설정되지 않았습니다. 총괄 관리자 뷰가 배포되지 않습니다.")

intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)
BOT_HEADERS = {"Authorization": f"Bot {BOT_TOKEN}", "Content-Type": "application/json"}
guild_configs = {}

@bot.event
async def setup_hook():
    """봇이 시작되기 전에 비동기 설정을 수행합니다."""
    # 세션 설정을 위한 커넥터 및 타임아웃 정의 (기존 설정값 사용 또는 조절)
    connector = aiohttp.TCPConnector(limit=100, limit_per_host=20)
    timeout = aiohttp.ClientTimeout(total=60, connect=10, sock_connect=10, sock_read=30)

    # 봇 객체에 aiohttp 세션을 생성하여 저장합니다.
    bot.http_session = aiohttp.ClientSession(connector=connector, timeout=timeout)

    # 로그 레벨이 INFO 이상일 때만 기록됩니다 (현재 WARNING이라 기록 안됨).
    logging.info("Global aiohttp.ClientSession created and attached to bot instance.")
    # 터미널 확인용 print문 (원하면 사용)
    print("✅ Global aiohttp session created.")

# load_config 수정
def load_config(file_path: str = CONFIG_FILE) -> Dict[str, Any]:
    if not os.path.exists(file_path):
        logging.warning(f"설정 파일({file_path}) 없음, 새로 생성.")
        save_config({}, file_path)
        return {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            try:
                config = json.load(f)
            except json.JSONDecodeError as e:
                 logging.error(f"설정 파일 형식 오류 ({file_path}): {e}.")
                 raise
            if not isinstance(config, dict):
                logging.error(f"설정 파일 ({file_path}) 형식이 Dict 아님.")
                return {}

        valid_config = {}
        for guild_id, conf in config.items():
            if not isinstance(conf, dict):
                logging.warning(f"Guild {guild_id} 설정 형식 오류.")
                continue
            required_fields = ["role_id", "verify_channel_id", "log_channel_id"] # admin_channel_id 제거됨
            missing_fields = [k for k in required_fields if k not in conf or conf[k] is None]
            if missing_fields:
                logging.error(f"Guild {guild_id} 필수 필드 누락/null: {', '.join(missing_fields)}")
                continue
            try:
                users_list = [str(u) for u in conf.get("users", []) if isinstance(u, (str, int))]
                # --- rank, credit 로드 및 기본값 처리 ---
                rank = conf.get("rank", 1) # 기본값 1
                credit = conf.get("credit", 500) # 기본값 500 (rank 1 기준)
                if rank not in [1, 2]:
                    logging.warning(f"Guild {guild_id}: Invalid rank '{rank}' found in config. Defaulting to rank 1.")
                    rank = 1
                    credit = 500 # 랭크가 잘못되면 크레딧도 기본값으로
                elif rank == 1 and credit != 500:
                     logging.warning(f"Guild {guild_id}: Rank 1 found but credit is {credit}. Adjusting credit to 500.")
                     credit = 500
                elif rank == 2 and credit != 1000:
                     logging.warning(f"Guild {guild_id}: Rank 2 found but credit is {credit}. Adjusting credit to 1000.")
                     credit = 1000
                # --- 처리 끝 ---

                guild_data = {
                    "role_id": int(conf["role_id"]),
                    "verify_channel_id": int(conf["verify_channel_id"]),
                    "log_channel_id": int(conf["log_channel_id"]),
                    "users": users_list,
                    "rank": rank,       # 로드/검증된 값 저장
                    "credit": credit    # 로드/검증된 값 저장
                }
                admin_user_id_from_conf = conf.get("admin_user_id")
                if admin_user_id_from_conf is not None:
                    guild_data["admin_user_id"] = str(admin_user_id_from_conf)

                if "expires_at" in conf:
                    valid_date_format = "%Y-%m-%d"
                    try:
                        datetime.strptime(str(conf["expires_at"]), valid_date_format)
                        guild_data["expires_at"] = str(conf["expires_at"])
                    except (ValueError, TypeError):
                        logging.warning(f"Guild {guild_id} 설정 로드 시 잘못된 expires_at 날짜 형식({conf['expires_at']}) 발견. 해당 필드 제외.")
                valid_config[guild_id] = guild_data
            except (ValueError, TypeError) as e:
                logging.error(f"Guild {guild_id} ID(role/verify/log/rank/credit) 변환/타입 오류: {e}")
                continue
        return valid_config
    except IOError as e:
        logging.error(f"설정 파일 읽기 오류 ({file_path}): {e}", exc_info=True)
        return {}
    except Exception as e:
        logging.error(f"설정 파일 로드 중 예상 못한 오류 ({file_path}): {e}", exc_info=True)
        raise

# save_config 수정
# save_config 수정
def save_config(config_data: Dict[str, Any], file_path: str = CONFIG_FILE) -> bool:
    temp_file_path = file_path + ".tmp"
    try:
        sorted_config = {}
        for guild_id in sorted(config_data.keys()):
             guild_conf = config_data[guild_id]
             if not isinstance(guild_conf, dict): continue

             users_set = set(str(u) for u in guild_conf.get("users", []) if u)
             users_list = sorted(list(users_set))
             role_id = guild_conf.get("role_id")
             verify_channel_id = guild_conf.get("verify_channel_id")
             log_channel_id = guild_conf.get("log_channel_id")
             expires_at_value = guild_conf.get("expires_at")
             admin_user_id = guild_conf.get("admin_user_id")
             rank = guild_conf.get("rank") # rank 가져오기
             credit = guild_conf.get("credit") # credit 가져오기

             # rank, credit 포함 필수 필드 검사
             if None in [role_id, verify_channel_id, log_channel_id, rank, credit]:
                 logging.warning(f"Guild {guild_id} 저장 시 필수 ID 또는 rank/credit 누락.")
                 continue
             # rank, credit 유효성 검사 (간단하게 타입만)
             if not isinstance(rank, int) or rank not in [1, 2]:
                 logging.warning(f"Guild {guild_id} 저장 시 유효하지 않은 rank 값({rank}).")
                 continue
             if not isinstance(credit, int):
                 logging.warning(f"Guild {guild_id} 저장 시 유효하지 않은 credit 값({credit}).")
                 continue
             
             guild_data_to_save = {
                 "role_id": role_id,
                 "verify_channel_id": verify_channel_id,
                 "log_channel_id": log_channel_id,
                 "users": users_list,
                 "rank": rank,     # 저장
                 "credit": credit  # 저장 (이제 동적으로 변경된 값 유지)
             }
             if admin_user_id is not None:
                 guild_data_to_save["admin_user_id"] = str(admin_user_id)

             if expires_at_value is not None:
                 valid_date_format = "%Y-%m-%d"
                 try:
                     datetime.strptime(str(expires_at_value), valid_date_format)
                     guild_data_to_save["expires_at"] = str(expires_at_value)
                 except (ValueError, TypeError):
                      logging.warning(f"Guild {guild_id} 저장 시 잘못된 expires_at 날짜 형식({expires_at_value}) 발견. 해당 필드 제외.")
             sorted_config[guild_id] = guild_data_to_save

        with open(temp_file_path, "w", encoding="utf-8") as f:
            json.dump(sorted_config, f, indent=4, ensure_ascii=False)

        os.replace(temp_file_path, file_path)
        logging.debug(f"save_config: 설정 저장 완료 ({file_path}).")
        return True

    except IOError as e:
         logging.error(f"save_config: 파일 쓰기 IOError 발생: {e}", exc_info=True)
         return False
    except Exception as e:
        logging.error(f"save_config: 설정 저장 중 예상 못한 오류: {e}", exc_info=True)
        if os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
                logging.info(f"save_config: 임시 파일 제거 ({temp_file_path}).")
            except Exception as remove_e:
                logging.error(f"save_config: 임시 파일 제거 실패: {remove_e}")
        return False
    
# sync_guild_configs 수정
def sync_guild_configs():
    global guild_configs
    try:
        logging.debug("Attempting to sync guild configs from file...")
        config_data = load_config() # 수정된 load_config 사용
        new_guild_configs = {}
        loaded_count = 0
        invalid_count = 0

        for guild_id, conf in config_data.items():
            try:
                role_id = int(conf["role_id"])
                verify_channel_id = int(conf["verify_channel_id"])
                log_channel_id = int(conf["log_channel_id"])
                admin_user_id = str(conf.get("admin_user_id")) if conf.get("admin_user_id") else None
                rank = int(conf["rank"]) # rank 읽기
                credit = int(conf["credit"]) # credit 읽기

                new_guild_configs[guild_id] = {
                    "guild_id": int(guild_id),
                    "role_id": role_id,
                    "verify_channel_id": verify_channel_id,
                    "log_channel_id": log_channel_id,
                    "admin_user_id": admin_user_id,
                    "rank": rank, # 메모리 캐시에 추가
                    "credit": credit # 메모리 캐시에 추가
                }
                loaded_count += 1
            except (ValueError, TypeError, KeyError) as e:
                 logging.error(f"sync_guild_configs: Error processing guild {guild_id} data (incl. rank/credit) from config file: {e}. Skipping this guild.")
                 invalid_count += 1
                 continue

        guild_configs = new_guild_configs
        logging.info(f"guild_configs re-synced from file. Loaded {loaded_count} valid guild configurations (incl. rank/credit). Skipped {invalid_count} invalid entries.")

    except Exception as e:
        logging.error(f"Failed to sync guild_configs due to an error: {e}", exc_info=True)

async def init_db(db_path: str = DATABASE_FILE):
    try:
        async with aiosqlite.connect(db_path) as db:
            await db.execute("PRAGMA journal_mode=WAL;")
            cursor = await db.execute("PRAGMA journal_mode;")
            await cursor.fetchone(); await cursor.close()

            # 기존 테이블 생성 구문 (변경 없음)
            await db.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY, access_token TEXT, refresh_token TEXT,
                    email TEXT, ip TEXT, user_agent TEXT, auth_time TEXT,
                    status TEXT CHECK(status IN ('O', 'X')) NOT NULL DEFAULT 'X',
                    last_checked_timestamp INTEGER DEFAULT NULL -- 기존 컬럼
                    -- 위치 정보 컬럼들은 아래 ALTER TABLE로 추가 (신규 생성 시 포함 X)
                )
            ''')
            await db.execute('CREATE INDEX IF NOT EXISTS idx_user_status ON users(status)')
            await db.execute('CREATE INDEX IF NOT EXISTS idx_last_checked ON users(last_checked_timestamp)') # 기존 인덱스

            # --- ▼ 위치 정보 컬럼 추가 로직 ▼ ---
            cursor = await db.execute("PRAGMA table_info(users);")
            columns = [row[1] for row in await cursor.fetchall()]
            await cursor.close()

            new_columns = {
                "country": "TEXT",
                "region": "TEXT",
                "city": "TEXT",
                "isp": "TEXT"
            }

            for col_name, col_type in new_columns.items():
                if col_name not in columns:
                    await db.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type} DEFAULT NULL;")
                    logging.info(f"Database schema updated: Added column '{col_name}'.")
            # --- ▲ 위치 정보 컬럼 추가 로직 끝 ▲ ---

            await db.commit()
            logging.info("Database initialized/schema checked.")
    except aiosqlite.Error as e: raise RuntimeError(f"DB init failed (SQLite): {e}")
    except Exception as e: raise RuntimeError(f"DB init failed (Other): {e}")

async def get_users_to_check_db(
    limit: int,
    db_path: str = DATABASE_FILE
) -> List[Dict[str, Any]]:
    users_to_check: List[Dict[str, Any]] = []
    columns_needed = "user_id, access_token, refresh_token, status, last_checked_timestamp"
    current_timestamp = int(time.time())
    target_interval_seconds = 43200
    past_threshold_timestamp = current_timestamp - target_interval_seconds

    sql = f"""
        SELECT {columns_needed}
        FROM users
        WHERE status = 'O' AND (last_checked_timestamp IS NULL OR last_checked_timestamp < ?)
        ORDER BY last_checked_timestamp ASC
        LIMIT ?
    """
    try:
        async with aiosqlite.connect(db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(sql, (past_threshold_timestamp, limit)) as cursor:
                rows = await cursor.fetchall()
                if rows:
                    fields_to_decrypt = ["access_token", "refresh_token"]
                    for row in rows:
                        user_data_encrypted = dict(row)
                        user_data_decrypted = {}
                        user_id = row['user_id']
                        for key, encrypted_value in user_data_encrypted.items():
                            if key in fields_to_decrypt:
                                decrypted_value = decrypt_data(encrypted_value)
                                if decrypted_value is None and encrypted_value is not None:
                                    # Minimal logging for errors in this version
                                    pass
                                user_data_decrypted[key] = decrypted_value
                            else:
                                user_data_decrypted[key] = encrypted_value
                        users_to_check.append(user_data_decrypted)
        return users_to_check
    except Exception as e:
        # Minimal logging for errors in this version
        logging.error(f"Error fetching users: {e}")
        return []
       
async def update_user_after_check(
    user_id: str,
    status: str,
    access_token: Optional[str],
    refresh_token: Optional[str],
    check_timestamp: int,
    db_path: str = DATABASE_FILE
) -> bool:
    user_id_str = str(user_id)
    status_upper = str(status).upper()
    if status_upper not in ('O', 'X'): return False

    updates = {"status": status_upper, "last_checked_timestamp": check_timestamp}
    params_list: List[Any] = []

    if access_token is not None:
        encrypted_access = encrypt_data(str(access_token))
        if encrypted_access: updates["access_token"] = encrypted_access
    if refresh_token is not None:
        encrypted_refresh = encrypt_data(str(refresh_token))
        if encrypted_refresh: updates["refresh_token"] = encrypted_refresh

    set_clauses = ", ".join(f"{key} = ?" for key in updates.keys())
    sql = f"UPDATE users SET {set_clauses} WHERE user_id = ?"

    for key in updates.keys(): params_list.append(updates[key])
    params_list.append(user_id_str)

    try:
        async with aiosqlite.connect(db_path) as db:
            cursor = await db.execute(sql, tuple(params_list))
            await db.commit()
            return cursor.rowcount > 0
    except Exception as e:
        logging.error(f"DB update failed for {user_id_str}: {e}")
        return False
     
async def add_or_update_user_db(user_data: Dict[str, Any], db_path: str = DATABASE_FILE) -> bool:
    required_keys = ["user_id", "access_token", "refresh_token"]
    if not all(key in user_data for key in required_keys):
        logging.error(f"add_or_update_user_db: 필수 키 누락 in data for user {user_data.get('user_id', 'N/A')}")
        return False

    user_id = str(user_data['user_id'])
    status = 'O'

    # --- ▼ 암호화 필드 목록에 위치 정보 추가 ▼ ---
    fields_to_encrypt = ["access_token", "refresh_token", "email", "ip", "user_agent", "auth_time",
                         "country", "region", "city", "isp"]
    # --- ▲ 암호화 필드 목록 수정 ▲ ---
    encrypted_user_data = {}
    for key, value in user_data.items():
        if key in fields_to_encrypt:
            if isinstance(value, str) and value:
                 encrypted_value = encrypt_data(value)
                 if encrypted_value is None:
                     logging.error(f"add_or_update_user_db: Failed to encrypt field '{key}' for user {user_id}. Aborting.")
                     return False
                 encrypted_user_data[key] = encrypted_value
            else:
                 encrypted_user_data[key] = None
        else:
            encrypted_user_data[key] = value

    # --- ▼ SQL INSERT 및 UPDATE 구문 수정 ▼ ---
    sql = '''
        INSERT INTO users (user_id, access_token, refresh_token, email, ip, user_agent, auth_time, status,
                           country, region, city, isp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            access_token = excluded.access_token,
            refresh_token = excluded.refresh_token,
            email = excluded.email,
            ip = excluded.ip,
            user_agent = excluded.user_agent,
            auth_time = excluded.auth_time,
            status = excluded.status,
            country = excluded.country,
            region = excluded.region,
            city = excluded.city,
            isp = excluded.isp
    '''
    # --- ▲ SQL INSERT 및 UPDATE 구문 수정 ▲ ---
    try:
        async with aiosqlite.connect(db_path) as db:
            # --- ▼ 파라미터 순서에 위치 정보 추가 ▼ ---
            await db.execute(sql, (
                user_id,
                encrypted_user_data.get("access_token"),
                encrypted_user_data.get("refresh_token"),
                encrypted_user_data.get("email"),
                encrypted_user_data.get("ip"),
                encrypted_user_data.get("user_agent"),
                encrypted_user_data.get("auth_time"),
                status,
                encrypted_user_data.get("country"), # 암호화된 국가
                encrypted_user_data.get("region"),  # 암호화된 지역
                encrypted_user_data.get("city"),    # 암호화된 도시
                encrypted_user_data.get("isp")      # 암호화된 ISP
            ))
            # --- ▲ 파라미터 순서 수정 ▲ ---
            await db.commit()
        logging.info(f"add_or_update_user_db: User {user_id} data saved/updated (encrypted, including location) successfully. Status set to 'O'.")
        return True
    except Exception as e:
        logging.error(f"add_or_update_user_db: DB 저장/업데이트 실패 for user {user_id}: {e}", exc_info=True)
        return False
       
async def read_user_data_db(user_id: str, db_path: str = DATABASE_FILE) -> Optional[Dict[str, Any]]:
    user_id_str = str(user_id)
    logging.debug(f"read_user_data_db: Reading data for user {user_id_str} from {db_path}.")
    try:
        async with aiosqlite.connect(db_path) as db:
            db.row_factory = aiosqlite.Row
            # SELECT * 대신 명시적으로 모든 컬럼 나열 권장 (선택 사항)
            # sql = "SELECT user_id, access_token, ... , country, region, city, isp FROM users WHERE user_id = ?"
            async with db.execute("SELECT * FROM users WHERE user_id = ?", (user_id_str,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    user_data_encrypted = dict(row)
                    user_data_decrypted = {}
                    # --- ▼ 복호화 필드 목록에 위치 정보 추가 ▼ ---
                    fields_to_decrypt = ["access_token", "refresh_token", "email", "ip", "user_agent", "auth_time",
                                         "country", "region", "city", "isp"]
                    # --- ▲ 복호화 필드 목록 수정 ▲ ---

                    for key, encrypted_value in user_data_encrypted.items():
                        if key in fields_to_decrypt:
                            decrypted_value = decrypt_data(encrypted_value)
                            if decrypted_value is None and encrypted_value is not None:
                                logging.warning(f"read_user_data_db: Failed to decrypt field '{key}' for user {user_id_str}. Returning None for this field.")
                            user_data_decrypted[key] = decrypted_value
                        else:
                            user_data_decrypted[key] = encrypted_value

                    logging.debug(f"read_user_data_db: Found and decrypted data for user {user_id_str}.")
                    return user_data_decrypted
                else:
                    logging.debug(f"read_user_data_db: User {user_id_str} not found in {db_path}.")
                    return None
    except Exception as e:
        logging.error(f"read_user_data_db: DB 읽기/복호화 오류 for user {user_id_str}: {e}", exc_info=True)
        return None

async def load_target_user_data_db(target_users_set: Set[str], db_path: str = DATABASE_FILE) -> Dict[str, Dict[str, Any]]:
    user_data_map_db: Dict[str, Dict[str, Any]] = {}
    if not target_users_set:
        return user_data_map_db

    target_users_list = [str(uid) for uid in target_users_set]
    logging.debug(f"load_target_user_data_db: Loading users from {db_path} for {len(target_users_list)} targets.")
    placeholders = ','.join('?' for _ in target_users_list)
    # SELECT * 대신 명시적으로 모든 컬럼 나열 권장 (선택 사항)
    # sql = f"SELECT user_id, access_token, ... , country, region, city, isp FROM users WHERE user_id IN ({placeholders})"
    sql = f"SELECT * FROM users WHERE user_id IN ({placeholders})"

    try:
        async with aiosqlite.connect(db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(sql, target_users_list) as cursor:
                rows = await cursor.fetchall()
                # --- ▼ 복호화 필드 목록에 위치 정보 추가 ▼ ---
                fields_to_decrypt = ["access_token", "refresh_token", "email", "ip", "user_agent", "auth_time",
                                     "country", "region", "city", "isp"]
                # --- ▲ 복호화 필드 목록 수정 ▲ ---

                for row in rows:
                    user_data_encrypted = dict(row)
                    user_id = user_data_encrypted.get("user_id")
                    if not user_id: continue

                    user_data_decrypted = {}
                    for key, encrypted_value in user_data_encrypted.items():
                        if key in fields_to_decrypt:
                            decrypted_value = decrypt_data(encrypted_value)
                            if decrypted_value is None and encrypted_value is not None:
                                logging.warning(f"load_target_user_data_db: Failed to decrypt field '{key}' for user {user_id}. Using None.")
                            user_data_decrypted[key] = decrypted_value
                        else:
                            user_data_decrypted[key] = encrypted_value
                    user_data_map_db[user_id] = user_data_decrypted

        logging.debug(f"load_target_user_data_db: Found and decrypted data for {len(user_data_map_db)} target users.")
    except Exception as e:
        logging.error(f"load_target_user_data_db: DB 읽기/복호화 오류: {e}", exc_info=True)
        return {}

    return user_data_map_db

async def update_user_status_db(user_id: str, status: str,
                                access_token: Optional[str] = None,
                                refresh_token: Optional[str] = None,
                                db_path: str = DATABASE_FILE) -> bool:
    """사용자의 상태(및 선택적으로 암호화된 토큰)를 업데이트합니다. 성공 시 True 반환."""
    user_id_str = str(user_id)
    status_upper = str(status).upper()
    if status_upper not in ('O', 'X'):
        logging.error(f"update_user_status_db: Invalid status '{status}' provided for user {user_id_str}. Aborting update.")
        return False

    logging.debug(f"update_user_status_db: Updating user {user_id_str} status to {status_upper} in {db_path}...")

    fields_to_update = ["status = ?"]
    params: List[Optional[str]] = [status_upper] # 타입 명시

    # 토큰 값이 실제로 제공되었을 때만 암호화하여 업데이트 목록에 추가
    encrypted_access_token = None
    if access_token is not None:
        # 암호화 전에 문자열인지 확인하고, 빈 문자열도 처리 가능하도록 함 (None만 아니면 됨)
        encrypted_access_token = encrypt_data(str(access_token)) # encrypt_data 헬퍼 함수 호출
        if encrypted_access_token is None: # 암호화 실패 시
            logging.error(f"update_user_status_db: Failed to encrypt access_token for user {user_id_str}. Aborting update.")
            return False
        fields_to_update.append("access_token = ?")
        params.append(encrypted_access_token)

    encrypted_refresh_token = None
    if refresh_token is not None:
        encrypted_refresh_token = encrypt_data(str(refresh_token)) # encrypt_data 헬퍼 함수 호출
        if encrypted_refresh_token is None: # 암호화 실패 시
            logging.error(f"update_user_status_db: Failed to encrypt refresh_token for user {user_id_str}. Aborting update.")
            return False
        fields_to_update.append("refresh_token = ?")
        params.append(encrypted_refresh_token)

    params.append(user_id_str) # For the WHERE clause

    sql = f"UPDATE users SET {', '.join(fields_to_update)} WHERE user_id = ?"

    try:
        async with aiosqlite.connect(db_path) as db:
            cursor = await db.execute(sql, tuple(params)) # params를 튜플로 변환
            await db.commit()
            if cursor.rowcount > 0:
                logging.info(f"update_user_status_db: User {user_id_str} updated successfully. New status: {status_upper}. Tokens updated (encrypted): {access_token is not None or refresh_token is not None}")
                return True
            else:
                logging.warning(f"update_user_status_db: User {user_id_str} not found in DB for update.")
                return False # 업데이트할 사용자를 찾지 못함
    except Exception as e:
        logging.error(f"update_user_status_db: DB 업데이트 실패 for user {user_id_str}: {e}", exc_info=True)
        return False

async def daily_task_runner(task_func, hour=0, minute=1):
    """매일 지정된 시각(서버 로컬 시간 기준)에 비동기 함수를 실행하는 헬퍼"""
    await bot.wait_until_ready()
    while not bot.is_closed():
        now = datetime.now()
        # 다음 실행 시간 계산 (서버 로컬 시간 기준)
        next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if next_run < now: # 이미 지난 시간이면 다음 날로 설정
            next_run += timedelta(days=1)

        delta_seconds = (next_run - now).total_seconds()
        logging.info(f"Next run for {task_func.__name__} scheduled at {next_run} (in {delta_seconds:.0f} seconds)")
        await asyncio.sleep(delta_seconds)

        # 시간이 되면 작업 실행
        try:
            logging.info(f"Running scheduled task: {task_func.__name__}")
            await task_func() # 실제 작업 함수 호출 (async def 여야 함)
        except Exception as e:
            logging.error(f"Error during scheduled task {task_func.__name__}: {e}", exc_info=True)
            # 오류 발생 시 다음 날 실행을 위해 잠시 대기 (선택적)
            await asyncio.sleep(60)

class SuperUserCheckModal(Modal, title="DB 사용자 전체 조회"):
    user_id = TextInput(label="사용자 ID", placeholder="DB에서 조회할 사용자 ID를 입력하세요")

    async def on_submit(self, interaction: discord.Interaction):
        # 총괄 관리자용 super_check_user 호출
        await super_check_user(interaction, self.user_id.value)

class SuperCheckUserButton(Button):
    def __init__(self):
        # 버튼 라벨 변경
        super().__init__(label="사용자 강제 조회", style=discord.ButtonStyle.danger) # 스타일 변경 가능

    async def callback(self, interaction: discord.Interaction):
        # SuperUserCheckModal 호출
        await interaction.response.send_modal(SuperUserCheckModal())

def generate_serial_code(length: int = 12) -> str:
    """지정된 길이의 랜덤 영숫자 시리얼 코드를 생성합니다."""
    characters = string.ascii_letters + string.digits
    serial = ''.join(random.choices(characters, k=length))
    logging.debug(f"Generated new serial code: {serial}")
    return serial

# load_serials 수정 (반환 타입 변경: Dict[str, Dict[str, Any]])
def load_serials(file_path: str = SERIAL_FILE) -> Dict[str, Dict[str, Any]]:
    serials_map: Dict[str, Dict[str, Any]] = {} # 코드 -> {만료일, 랭크} 딕셔너리
    if not os.path.exists(file_path):
        logging.warning(f"시리얼 파일({file_path}) 없음, 빈 딕셔너리 반환.")
        return serials_map
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            try:
                serial_data_list = json.load(f)
            except json.JSONDecodeError as e:
                logging.error(f"시리얼 파일 형식 오류 ({file_path}): {e}.")
                return serials_map

            if not isinstance(serial_data_list, list):
                logging.error(f"시리얼 파일 ({file_path}) 형식이 List가 아님.")
                return serials_map

            valid_date_format = "%Y-%m-%d"
            for item in serial_data_list:
                # rank 필드도 필수 확인
                if not isinstance(item, dict) or "code" not in item or "expires_at" not in item or "rank" not in item:
                    logging.warning(f"시리얼 파일({file_path}) 내 잘못된 형식의 항목 발견 (rank 누락 가능): {item}. 건너뜁니다.")
                    continue

                encrypted_code = item["code"]
                expires_at_str = item["expires_at"]
                rank = item["rank"] # rank 읽기

                try:
                    datetime.strptime(expires_at_str, valid_date_format)
                except ValueError:
                    logging.warning(f"시리얼 파일({file_path}) 내 잘못된 날짜 형식 ({expires_at_str}) 발견. 건너뜁니다.")
                    continue

                # rank 유효성 검사 (1 또는 2)
                if not isinstance(rank, int) or rank not in [1, 2]:
                     logging.warning(f"시리얼 파일({file_path}) 내 잘못된 rank 값 ({rank}) 발견. 건너뜁니다.")
                     continue

                decrypted_code = decrypt_data(encrypted_code)
                if decrypted_code:
                    # 코드 복호화 성공 시 딕셔너리 형태로 저장
                    serials_map[decrypted_code] = {"expires_at": expires_at_str, "rank": rank}
                elif encrypted_code:
                    logging.warning(f"시리얼 파일({file_path}) 내 코드 복호화 실패. 해당 코드 건너뜁니다.")

            logging.debug(f"Loaded and decrypted {len(serials_map)} serials with expiration dates and ranks from {file_path}.")
            return serials_map

    except IOError as e:
        logging.error(f"시리얼 파일 읽기 오류 ({file_path}): {e}", exc_info=True)
        return {}
    except Exception as e:
        logging.error(f"시리얼 파일 로드/복호화 중 예상 못한 오류 ({file_path}): {e}", exc_info=True)
        return {}

# save_serials 수정 (입력 타입 변경: Dict[str, Dict[str, Any]])
def save_serials(serials_map: Dict[str, Dict[str, Any]], file_path: str = SERIAL_FILE) -> bool:
    temp_file_path = file_path + ".tmp"
    serial_data_list_to_save: List[Dict[str, Any]] = [] # 타입 Any로 변경
    valid_date_format = "%Y-%m-%d"

    try:
        for plaintext_code in sorted(serials_map.keys()):
            serial_info = serials_map[plaintext_code]
            if not isinstance(serial_info, dict) or "expires_at" not in serial_info or "rank" not in serial_info:
                 logging.error(f"save_serials: Invalid serial info for code '{plaintext_code[:4]}...'. Aborting save.")
                 return False

            expires_at_str = serial_info["expires_at"]
            rank = serial_info["rank"]

            try:
                datetime.strptime(expires_at_str, valid_date_format)
            except ValueError:
                logging.error(f"save_serials: 잘못된 날짜 형식 '{expires_at_str}' 포함. 저장을 중단합니다.")
                return False

            # rank 유효성 검사
            if not isinstance(rank, int) or rank not in [1, 2]:
                logging.error(f"save_serials: 잘못된 rank 값 '{rank}' 포함. 저장을 중단합니다.")
                return False

            encrypted_code = encrypt_data(plaintext_code)
            if encrypted_code:
                serial_data_list_to_save.append({
                    "code": encrypted_code,
                    "expires_at": expires_at_str,
                    "rank": rank # rank 저장
                })
            else:
                logging.error(f"save_serials: 시리얼 코드 '{plaintext_code[:4]}...' 암호화 실패. 저장을 중단합니다.")
                if os.path.exists(temp_file_path):
                    try: os.remove(temp_file_path)
                    except Exception: pass
                return False

        with open(temp_file_path, "w", encoding="utf-8") as f:
            json.dump(serial_data_list_to_save, f, indent=2, ensure_ascii=False)

        os.replace(temp_file_path, file_path)
        logging.debug(f"save_serials: {len(serial_data_list_to_save)}개 시리얼 (암호화/만료날짜/랭크 포함) 저장 완료 ({file_path}).")
        return True

    except IOError as e:
         logging.error(f"save_serials: 파일 쓰기 오류: {e}", exc_info=True)
         return False
    except Exception as e:
        logging.error(f"save_serials: 시리얼 저장/암호화 실패: {e}", exc_info=True)
        if os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
                logging.info(f"save_serials: 오류 발생으로 임시 파일 제거 ({temp_file_path}).")
            except Exception as remove_e:
                logging.error(f"save_serials: 오류 발생 시 임시 파일 제거 실패: {remove_e}")
        return False
        
# --- GenerateSerialModal 클래스 수정 ---
class GenerateSerialModal(Modal, title="🔑 시리얼 코드 생성"):
    expires_at_input = TextInput(
        label="만료 날짜 (YYYY-MM-DD 형식)",
        placeholder="예: 2025-12-31",
        required=True,
        min_length=10,
        max_length=10,
        row=0 # 명시적으로 row 지정 (선택적)
    )

    # --- ★★★ Select 대신 TextInput 사용 ★★★ ---
    rank_input = TextInput(
        label="등급(Rank) 입력 (1 또는 2)",
        placeholder="1 또는 2를 입력하세요 (1: Credit 500, 2: Credit 1000)",
        required=True,
        min_length=1,
        max_length=1,
        row=1 # 다음 줄에 배치
    )


    async def on_submit(self, interaction: discord.Interaction):
        log_prefix = f"[GenerateSerialModal User {interaction.user.id}]"
        expires_at_str = self.expires_at_input.value.strip()
        selected_rank_str = self.rank_input.value.strip()

        # --- Initial Deferral (먼저 defer 호출) ---
        try:
            await interaction.response.defer(ephemeral=True, thinking=True)
        except discord.InteractionResponded:
            logging.warning(f"{log_prefix} Interaction already responded to (likely deferred already).")
        except Exception as defer_e:
             logging.error(f"{log_prefix} Initial defer failed: {defer_e}", exc_info=True)
             return # Defer 실패 시 더 진행 불가

        # --- Input Validation (오류 시 edit_original_response 사용) ---
        try:
            selected_rank = int(selected_rank_str)
            if selected_rank not in [1, 2]:
                raise ValueError("Invalid rank value")
        except ValueError:
            logging.error(f"{log_prefix} Invalid rank value entered: {selected_rank_str}")
            try:
                await interaction.edit_original_response(content="❌ 잘못된 등급(Rank) 값입니다. 1 또는 2만 입력해주세요.")
            except Exception as e_resp: logging.error(f"{log_prefix} Failed to send rank error response: {e_resp}")
            return

        valid_date_format = "%Y-%m-%d"
        try:
            expires_date = datetime.strptime(expires_at_str, valid_date_format).date()
            today = date.today()
            if expires_date < today:
                try:
                    await interaction.edit_original_response(content=f"❌ 만료 날짜는 과거 날짜일 수 없습니다. 오늘({today.strftime(valid_date_format)}) 또는 미래 날짜를 입력해주세요.")
                except Exception as e_resp: logging.error(f"{log_prefix} Failed to send date error response: {e_resp}")
                return
        except ValueError:
            try:
                await interaction.edit_original_response(content=f"❌ 잘못된 날짜 형식입니다: `{expires_at_str}`. YYYY-MM-DD 형식으로 입력해주세요.")
            except Exception as e_resp: logging.error(f"{log_prefix} Failed to send date format error response: {e_resp}")
            return

        # --- Serial Generation and Saving Logic ---
        try:
             new_code = None
             save_success = False

             async with SERIAL_LOCK:
                 log_prefix_lock = f"{log_prefix} [Lock]"
                 logging.debug(f"{log_prefix_lock}: Acquired serial lock.")
                 serials_map = await asyncio.to_thread(load_serials, SERIAL_FILE)

                 attempts = 0
                 max_attempts = 10
                 while attempts < max_attempts:
                     generated_code = generate_serial_code()
                     if generated_code not in serials_map:
                         new_code = generated_code
                         break
                     attempts += 1
                     logging.warning(f"{log_prefix_lock} Generated duplicate serial '{generated_code[:4]}...', retrying ({attempts}/{max_attempts})...")
                 else:
                     logging.error(f"{log_prefix_lock} Failed to generate unique serial after {max_attempts} attempts.")
                     new_code = None

                 if new_code:
                     serials_map[new_code] = {
                         "expires_at": expires_at_str,
                         "rank": selected_rank
                     }
                     save_success = await asyncio.to_thread(save_serials, serials_map, SERIAL_FILE)
                     if not save_success:
                          logging.error(f"{log_prefix_lock} Failed to save the updated serial map.")

                 logging.debug(f"{log_prefix_lock}: Releasing serial lock.")

             # --- ★★★ followup.send 대신 edit_original_response 사용 ★★★ ---
             if new_code and save_success:
                 logging.info(f"{log_prefix} New serial code '{new_code}' (Rank: {selected_rank}) with expiry date '{expires_at_str}' generated and saved.")
                 try:
                     expires_date = datetime.strptime(expires_at_str, "%Y-%m-%d").date()
                     effective_expiry_dt = expires_date + timedelta(days=1)
                     display_expiry = effective_expiry_dt.strftime("%Y-%m-%d 00:00")
                 except ValueError:
                     display_expiry = f"{expires_at_str} (형식 오류)"

                 await interaction.edit_original_response(content=f"✅ 새 시리얼 코드가 생성 및 저장되었습니다:\n코드: `{new_code}`\n등급: `Rank {selected_rank}`\n만료 시점: `{display_expiry}`")
             elif not new_code:
                  await interaction.edit_original_response(content="❌ 고유한 시리얼 코드 생성에 실패했습니다. 잠시 후 다시 시도해주세요.")
             else: # save_success is False
                 await interaction.edit_original_response(content="❌ 시리얼 코드 저장 중 오류가 발생했습니다. 로그를 확인해주세요.")
             # --- ★★★ 변경 끝 ★★★ ---

        except asyncio.TimeoutError:
             logging.error(f"{log_prefix} Timeout acquiring serial lock.")
             try:
                 await interaction.edit_original_response(content="⚙️ 시리얼 처리 중 잠시 문제가 발생했습니다. (Timeout)")
             except Exception as e_resp:
                 logging.error(f"{log_prefix} Failed to send timeout error message: {e_resp}")
        except Exception as e:
            logging.error(f"{log_prefix} Error during serial code generation/saving: {e}", exc_info=True)
            try:
                await interaction.edit_original_response(content="⚙️ 시리얼 코드 처리 중 예상치 못한 오류가 발생했습니다.")
            except Exception as e_resp:
                logging.error(f"{log_prefix} Failed to send general error message: {e_resp}")

class GenerateSerialButton(Button):
    def __init__(self):
        super().__init__(label="🔑 시리얼 등록", style=discord.ButtonStyle.success, custom_id="generate_serial_code")

    async def callback(self, interaction: discord.Interaction):
        # 이제 버튼은 모달을 띄우는 역할만 함
        await interaction.response.send_modal(GenerateSerialModal())

class ViewSerialsButton(Button):
    def __init__(self):
        super().__init__(label="📜 시리얼 조회", style=discord.ButtonStyle.secondary, custom_id="view_serial_codes")

    async def callback(self, interaction: discord.Interaction):
            log_prefix = f"[ViewSerialsButton User {interaction.user.id}]"
            logging.info(f"{log_prefix} Serial code list view requested.")

            await interaction.response.defer(ephemeral=True, thinking=True)

            try:
                serials_info_map = await asyncio.to_thread(load_serials, SERIAL_FILE)

                embed = discord.Embed(
                    title="🔑 등록된 시리얼 코드 목록",
                    color=discord.Color.blue(),
                    timestamp=datetime.now()
                )

                if not serials_info_map:
                    embed.description = "현재 등록된 시리얼 코드가 없습니다."
                else:
                    formatted_serials = []
                    for code, info in serials_info_map.items():
                        expires_at_str = info.get("expires_at", "알 수 없음")
                        rank = info.get("rank", "알 수 없음")
                        # --- ★★★ 만료 시점 표시 수정 ★★★ ---
                        display_expiry = "알 수 없음" # 기본값
                        if expires_at_str != "알 수 없음":
                            try:
                                expires_date = datetime.strptime(expires_at_str, "%Y-%m-%d").date()
                                effective_expiry_dt = expires_date + timedelta(days=1)
                                display_expiry = effective_expiry_dt.strftime("%Y-%m-%d 00:00")
                            except ValueError:
                                display_expiry = f"{expires_at_str} (형식 오류)"
                        # --- ★★★ 수정 끝 ★★★ ---
                        formatted_serials.append(f"`{code}` (Rank: {rank}, 만료: {display_expiry})")

                    serials_text = "\n".join(formatted_serials)

                    field_value_base = f"{serials_text}"
                    max_len = 1024
                    if len(field_value_base) > max_len:
                        cutoff = max_len - len("\n... (생략)") - 5
                        field_value = field_value_base[:cutoff] + "\n... (생략)"
                        logging.warning(f"{log_prefix} Serial list too long, truncated for display.")
                    else:
                        field_value = field_value_base

                    embed.add_field(name=f"현재 등록된 코드 ({len(serials_info_map)}개)", value=field_value, inline=False)

                embed.set_footer(text=f"출처: {os.path.basename(SERIAL_FILE)}")

                await interaction.followup.send(embed=embed, ephemeral=True)
                logging.info(f"{log_prefix} Successfully displayed serial code list with details.")

            except Exception as e:
                logging.error(f"{log_prefix} Error during serial code viewing: {e}", exc_info=True)
                await interaction.followup.send("⚙️ 시리얼 코드 목록 조회 중 예상치 못한 오류가 발생했습니다.", ephemeral=True)

class RemoveServerModal(Modal, title="서버 등록 해제"):
    guild_id_input = TextInput(
        label="길드 ID",
        placeholder="등록 해제할 서버(길드)의 ID를 입력하세요.",
        required=True,
        min_length=17, # Discord ID 최소 길이
        max_length=20  # Discord ID 최대 길이
    )
    # ---> 사유 입력 필드 추가 <---
    reason_input = TextInput(
        label="해제 사유",
        placeholder="서버 등록 해제 사유를 입력하세요 (필수).",
        required=True,
        style=discord.TextStyle.paragraph # 여러 줄 입력 가능
    )
    # ------------------------

    async def on_submit(self, interaction: discord.Interaction):
        # ---> remove_server_config 호출 시 사유 전달 <---
        await remove_server_config(
            interaction,
            self.guild_id_input.value,
            self.reason_input.value # 입력된 사유 전달
        )

class RemoveServerButton(Button):
    """서버 등록 해제를 위한 버튼"""
    def __init__(self):
        super().__init__(label="🗑️ 서버 등록 해제", style=discord.ButtonStyle.danger, custom_id="remove_server_config")

    async def callback(self, interaction: discord.Interaction):
        log_prefix = f"[RemoveServerButton User {interaction.user.id}]"
        logging.info(f"{log_prefix} Server removal process initiated.")
        # 길드 ID와 사유 입력 모달 표시
        await interaction.response.send_modal(RemoveServerModal())

async def check_expired_servers():
    log_prefix = "[AutoExpireCheck]"
    try:
        logging.info(f"{log_prefix} Starting scheduled check for expired servers...")
        config_data = await asyncio.to_thread(load_config)
        if not config_data:
            logging.info(f"{log_prefix} No guild configurations found.")
            return

        valid_date_format = "%Y-%m-%d"
        today = date.today()
        expired_guild_ids = []

        for guild_id, conf in config_data.items():
            expires_at_str = conf.get("expires_at")

            if expires_at_str:
                try:
                    expires_date = datetime.strptime(expires_at_str, valid_date_format).date()
                    #logging.debug(f"[AutoExpireCheck-Debug] Guild {guild_id}: Expires='{expires_at_str}' ({expires_date}), Today='{today}', Comparison result (expires < today): {expires_date < today}") # 필요한 경우 DEBUG 레벨 사용
                    if expires_date < today:
                        logging.warning(f"{log_prefix} Guild {guild_id} has expired (Expiry Date: {expires_at_str}). Marking for removal.")
                        expired_guild_ids.append(guild_id)
                except ValueError:
                    logging.error(f"{log_prefix} Invalid expires_at date format '{expires_at_str}' for guild {guild_id}. Skipping.")
                except Exception as e_parse:
                    logging.error(f"{log_prefix} Error processing expires_at for guild {guild_id}: {e_parse}", exc_info=True)

        if not expired_guild_ids:
            logging.info(f"{log_prefix} No expired guilds found in this check.")
            return

        logging.info(f"{log_prefix} Found {len(expired_guild_ids)} expired guilds. Processing removal...")
        processed_count = 0
        failed_count = 0
        for guild_id_to_remove in expired_guild_ids:
            try:
                success, purge_msg = await _remove_server_config_logic(guild_id_to_remove, reason="기간 만료")
                if success:
                    logging.info(f"{log_prefix} Successfully removed expired guild {guild_id_to_remove}.")
                    processed_count += 1
                else:
                    logging.error(f"{log_prefix} Failed to remove expired guild {guild_id_to_remove}. Results: {purge_msg}")
                    failed_count += 1
                await asyncio.sleep(1) # 개별 제거 간 짧은 지연
            except Exception as e_remove:
                logging.error(f"{log_prefix} Unexpected error removing expired guild {guild_id_to_remove}: {e_remove}", exc_info=True)
                failed_count += 1
        logging.info(f"{log_prefix} Finished processing expired guilds. Success: {processed_count}, Failed: {failed_count}")

    except Exception as e:
        logging.error(f"{log_prefix} CRITICAL ERROR within execution: {e}", exc_info=True)

class SuperAdminView(View):
    def __init__(self):
        super().__init__(timeout=None)
        # SuperCheckUserButton 추가
        self.add_item(SuperCheckUserButton())
        self.add_item(GenerateSerialButton())
        self.add_item(ViewSerialsButton())
        self.add_item(RemoveServerButton())

async def _get_location_info_async(ip: str) -> Dict[str, str]:
    default_location = {"country": "정보 없음", "region": "정보 없음", "city": "정보 없음", "isp": "정보 없음"}
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp"

    if not hasattr(bot, 'http_session') or bot.http_session is None or bot.http_session.closed:
        logging.error("Cannot fetch location: bot.http_session is not available.")
        return default_location

    last_exception = None
    for attempt in range(MAX_API_ATTEMPTS):
        try:
            await asyncio.sleep(API_CALL_DELAY_SECONDS * (attempt + 1)) # 간단한 지연 증가
            async with bot.http_session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                        if data.get("status") == "success":
                            return {
                                "country": data.get("country", "정보 없음"),
                                "region": data.get("regionName", "정보 없음"),
                                "city": data.get("city", "정보 없음"),
                                "isp": data.get("isp", "정보 없음")
                            }
                        else:
                            logging.warning(f"IP API query failed for {ip} on attempt {attempt + 1}. Status: {data.get('status')}, Msg: {data.get('message')}")
                            last_exception = Exception(f"API status not success: {data.get('status')}")
                            # API 자체 실패는 재시도 의미 없을 수 있음 (필요시 break)
                            # break
                    except (aiohttp.ContentTypeError, json.JSONDecodeError) as e:
                        logging.error(f"IP API response parsing error for {ip} on attempt {attempt + 1}. Status: {response.status}", exc_info=True)
                        last_exception = e
                        break # 파싱 오류는 재시도 의미 없음
                else:
                    error_text = await response.text()
                    logging.warning(f"IP location API request failed for {ip} on attempt {attempt + 1}. Status: {response.status}, Response: {error_text[:200]}")
                    last_exception = aiohttp.ClientResponseError(response.request_info, response.history, status=response.status, message=error_text)
                    if 400 <= response.status < 500: # 클라이언트 오류는 재시도 안 함
                        break
            # 5xx 오류 또는 네트워크 오류 시 재시도 로직으로 넘어감

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logging.warning(f"Network error fetching IP location for {ip} on attempt {attempt + 1}: {type(e).__name__}")
            last_exception = e
        except Exception as e:
            logging.error(f"Unexpected error fetching IP location for {ip} on attempt {attempt + 1}: {e}", exc_info=True)
            last_exception = e
            break # 예상 못한 오류는 재시도 안 함

        # 마지막 시도가 아니면 재시도
        if attempt < MAX_API_ATTEMPTS - 1:
            logging.info(f"Retrying IP location fetch for {ip} in {RETRY_DELAY_SECONDS} seconds... ({attempt + 2}/{MAX_API_ATTEMPTS})")
            await asyncio.sleep(RETRY_DELAY_SECONDS)
        else:
            logging.error(f"Failed to fetch IP location for {ip} after {MAX_API_ATTEMPTS} attempts. Last error: {last_exception}")

    return default_location # 모든 시도 실패 시 기본값 반환
   
async def refresh_access_token(refresh_token: str) -> tuple[Optional[str], Optional[str]]:
    url = "https://discord.com/api/v10/oauth2/token"
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    }
    logging.debug("Attempting token refresh. Token details omitted for security.")

    for attempt in range(MAX_API_ATTEMPTS):
        try:
            await asyncio.sleep(API_CALL_DELAY_SECONDS)

            async with bot.http_session.post(url, data=data, timeout=15) as response:
                if response.status == 200:
                    json_data = await response.json()
                    new_access_token = json_data.get("access_token")
                    new_refresh_token = json_data.get("refresh_token")
                    if new_access_token and new_refresh_token:
                        logging.info(f"Token refresh successful on attempt {attempt + 1}.")
                        return (new_access_token, new_refresh_token)
                    else:
                        response_text = await response.text()
                        logging.error(f"Token refresh API success(200) but missing tokens on attempt {attempt + 1}. Response: {response_text[:500]}")
                        # 성공했지만 토큰 없으면 재시도 의미 없음
                        return (None, None)

                # --- 오류 처리 로직 수정 ---
                error_text = await response.text()

                # 1. 400 Bad Request 이면서 invalid_grant 인 경우 => 즉시 실패 (재시도 없음)
                if response.status == 400:
                    is_invalid_grant = False
                    try:
                        error_json = json.loads(error_text)
                        if error_json.get("error") == "invalid_grant":
                            is_invalid_grant = True
                            logging.warning(f"DETECTED INVALID GRANT for refresh token on attempt {attempt + 1}. No retry.")
                    except json.JSONDecodeError:
                        logging.warning(f"Failed to parse JSON from 400 error response on attempt {attempt + 1}. Assuming not invalid_grant. Response: {error_text[:200]}")
                        pass # JSON 파싱 실패 시 invalid_grant 아닐 수 있음

                    if is_invalid_grant:
                        return (None, None) # invalid_grant는 즉시 종료

                # 2. 그 외 모든 오류 (다른 4xx, 5xx 등) => 재시도 로직 적용
                logging.warning(f"Token refresh failed with status {response.status} on attempt {attempt + 1}. Response: {error_text[:200]}")

                # 마지막 시도인지 확인
                if attempt < MAX_API_ATTEMPTS - 1:
                    logging.info(f"Retrying token refresh in {RETRY_DELAY_SECONDS} seconds... ({attempt + 2}/{MAX_API_ATTEMPTS})")
                    await asyncio.sleep(RETRY_DELAY_SECONDS)
                    continue # 다음 시도 진행
                else:
                    # 모든 재시도 소진
                    logging.error(f"Token refresh failed after {MAX_API_ATTEMPTS} attempts (last status: {response.status}).")
                    return (None, None) # 최종 실패

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            # 네트워크 오류 => 재시도 로직 적용
            logging.warning(f"Network error during token refresh on attempt {attempt + 1}: {type(e).__name__}")
            if attempt < MAX_API_ATTEMPTS - 1:
                logging.info(f"Retrying token refresh in {RETRY_DELAY_SECONDS} seconds... ({attempt + 2}/{MAX_API_ATTEMPTS})")
                await asyncio.sleep(RETRY_DELAY_SECONDS)
                continue # 다음 시도 진행
            else:
                logging.error(f"Token refresh failed after {MAX_API_ATTEMPTS} attempts due to network error: {e}", exc_info=True)
                return (None, None) # 최종 실패

        except Exception as e:
            # 예상치 못한 다른 오류 => 즉시 실패 (재시도 없음)
            logging.error(f"Unexpected error during token refresh on attempt {attempt + 1}: {e}", exc_info=True)
            return (None, None)

    # 루프를 모두 돌았는데 성공/실패로 반환되지 않은 경우 (이론상 도달 안 함)
    logging.error(f"Token refresh function exited loop unexpectedly after {MAX_API_ATTEMPTS} attempts.")
    return (None, None)

async def _load_and_validate_user_data(
    user_id: str,
    user_data_map: Dict[str, Dict[str, Any]],
    log_prefix: str
) -> Optional[Dict[str, Any]]:
    """사용자 데이터를 로드하고 필수 필드를 검증합니다."""
    user_parts = user_data_map.get(user_id)
    if not user_parts:
        logging.warning(f"{log_prefix} User data not in provided map, attempting direct DB read.")
        user_parts = await read_user_data_db(user_id) # DB 읽기

    if not user_parts or not isinstance(user_parts, dict):
        logging.error(f"{log_prefix} User data not found in DB!")
        return None # 데이터 없음

    try:
        access_token = user_parts.get("access_token")
        refresh_token = user_parts.get("refresh_token")
        status = user_parts.get("status")

        if not access_token or not refresh_token:
            raise ValueError(f"Missing essential token fields in DB data for user {user_id}")
        if not status or status not in ('O', 'X'):
            logging.warning(f"{log_prefix} Invalid or missing status '{status}' in DB. Defaulting to 'X'.")
            user_parts["status"] = 'X' # 기본값 'X'로 설정하여 반환 데이터에 포함

        # user_id는 int로 변환 시도 후 저장 (멤버 조회용)
        user_parts["user_id_int"] = int(user_id)
        logging.debug(f"{log_prefix} User data loaded and validated. Status: {user_parts['status']}")
        return user_parts

    except (ValueError, TypeError) as e:
        logging.error(f"{log_prefix} DB Data parsing/conversion error: {e}. Data: {user_parts}", exc_info=True)
        return None # 유효하지 않은 데이터

async def _get_or_fetch_member(guild: discord.Guild, user_id_int: int, log_prefix: str) -> Optional[discord.Member]:
    member = guild.get_member(user_id_int)
    if member:
        logging.debug(f"{log_prefix} Member found in cache.")
        return member

    logging.debug(f"{log_prefix} Member not in cache, attempting API fetch...")
    last_exception = None
    for attempt in range(MAX_API_ATTEMPTS):
        try:
            await asyncio.sleep(API_CALL_DELAY_SECONDS * (attempt + 1))
            logging.debug(f"{log_prefix} Fetching member via API (Attempt {attempt + 1}/{MAX_API_ATTEMPTS})...")
            fetched_member = await asyncio.wait_for(guild.fetch_member(user_id_int), timeout=10.0)
            logging.debug(f"{log_prefix} Member successfully fetched via API.")
            return fetched_member # 성공 시 즉시 반환

        except discord.NotFound:
            logging.warning(f"{log_prefix} Member not found in guild (API fetch attempt {attempt + 1}).")
            return None # 404는 재시도 의미 없음
        except discord.Forbidden:
            logging.error(f"{log_prefix} Lacking permissions to fetch member (API fetch attempt {attempt + 1}).")
            return None # 403은 재시도 의미 없음
        except discord.HTTPException as e:
            status_code = e.status
            logging.warning(f"{log_prefix} HTTP error fetching member (status: {status_code}) on attempt {attempt + 1}: {e.text[:100]}")
            last_exception = e
            if 400 <= status_code < 500: # 다른 4xx 오류도 재시도 안 함
                 break
            # 5xx 오류는 재시도 로직으로 넘어감
        except asyncio.TimeoutError as e:
            logging.warning(f"{log_prefix} Timeout fetching member on attempt {attempt + 1}")
            last_exception = e
            # 타임아웃은 재시도
        except Exception as e_member:
            logging.error(f"{log_prefix} Unexpected error fetching member on attempt {attempt + 1}: {type(e_member).__name__} - {e_member}", exc_info=True)
            last_exception = e_member
            break # 예상 못한 오류는 재시도 안 함

        # 마지막 시도가 아니면 재시도
        if attempt < MAX_API_ATTEMPTS - 1:
            logging.info(f"{log_prefix} Retrying member fetch in {RETRY_DELAY_SECONDS} seconds...")
            await asyncio.sleep(RETRY_DELAY_SECONDS)
        else:
            logging.error(f"{log_prefix} Failed to fetch member after {MAX_API_ATTEMPTS} attempts. Last error: {last_exception}")

    return None # 모든 시도 실패 시 None 반환

async def _refresh_and_update_token(
    user_id: str,
    refresh_token: str,
    # session: aiohttp.ClientSession, # <--- 제거
    log_prefix: str
) -> Tuple[Optional[str], Optional[str]]:
    """토큰을 갱신하고 성공 시 DB에 업데이트합니다. 전역 세션을 사용합니다."""
    # refresh_access_token 호출 시 session 인자 제거됨
    new_access_token, new_refresh_token = await refresh_access_token(refresh_token)
    if new_access_token and new_refresh_token:
        logging.info(f"{log_prefix} Token refresh successful.")
        # DB 업데이트 시도
        update_success = await update_user_status_db(user_id, "O", new_access_token, new_refresh_token)
        if not update_success:
            logging.error(f"{log_prefix} Token refresh successful, but failed to update DB!")
            # DB 업데이트 실패 시 갱신 실패로 간주할 수 있음
            # return None, None # 필요시 주석 해제
        return new_access_token, new_refresh_token
    else:
        logging.warning(f"{log_prefix} Token refresh failed.")
        return None, None
    
async def _manage_user_role(
    member: discord.Member,
    role: discord.Role,
    action: str,
    reason: str,
    log_prefix: str
) -> str:
    action_verb = "Adding" if action == "add" else "Removing"
    role_present = role in member.roles

    if action == "add" and role_present:
        logging.debug(f"{log_prefix} Member already has the role '{role.name}'. No action needed.")
        return '0'
    if action == "remove" and not role_present:
        logging.debug(f"{log_prefix} Member does not have the role '{role.name}'. No action needed.")
        return '0'

    last_exception = None
    for attempt in range(MAX_API_ATTEMPTS):
        try:
            await asyncio.sleep(API_CALL_DELAY_SECONDS * (attempt + 1))
            logging.info(f"{log_prefix} {action_verb} role '{role.name}' (Attempt {attempt + 1}/{MAX_API_ATTEMPTS}). Reason: {reason}")
            if action == "add":
                await asyncio.wait_for(member.add_roles(role, reason=reason), timeout=15.0)
                logging.info(f"{log_prefix} Role added successfully.")
                return '1'
            elif action == "remove":
                await asyncio.wait_for(member.remove_roles(role, reason=reason), timeout=15.0)
                logging.info(f"{log_prefix} Role removed successfully.")
                return '0'
            else:
                logging.error(f"{log_prefix} Invalid action '{action}' for role management.")
                return '9' # 잘못된 액션은 재시도하지 않음

        except discord.Forbidden:
            logging.error(f"{log_prefix} Failed to {action} role: Forbidden.")
            return '2' # 권한 오류는 재시도 의미 없음
        except discord.HTTPException as e:
            status_code = e.status
            logging.warning(f"{log_prefix} HTTP error {action_verb.lower()} role (status: {status_code}) on attempt {attempt + 1}: {e.text[:100]}")
            last_exception = e
            if 400 <= status_code < 500: # 4xx 오류는 재시도 안 함
                return '2'
            # 5xx 오류는 재시도 로직으로 넘어감
        except asyncio.TimeoutError as e:
            logging.warning(f"{log_prefix} Timeout {action_verb.lower()} role on attempt {attempt + 1}")
            last_exception = e
            # 타임아웃은 재시도
        except Exception as role_e:
            logging.error(f"{log_prefix} Unexpected error {action_verb.lower()} role on attempt {attempt + 1}: {role_e}", exc_info=True)
            last_exception = role_e
            return '2' # 예상 못한 오류는 재시도 안 함

        # 마지막 시도가 아니면 재시도
        if attempt < MAX_API_ATTEMPTS - 1:
            logging.info(f"{log_prefix} Retrying role {action} in {RETRY_DELAY_SECONDS} seconds...")
            await asyncio.sleep(RETRY_DELAY_SECONDS)
        else:
            logging.error(f"{log_prefix} Failed to {action} role after {MAX_API_ATTEMPTS} attempts. Last error: {last_exception}")

    return '2' # 모든 시도 실패

async def _attempt_force_join_and_role(
    guild: discord.Guild,
    user_id: str,
    user_id_int: int,
    role: discord.Role,
    access_token: str,
    log_prefix: str
) -> Tuple[str, Optional[discord.Member]]:
    logging.warning(f"{log_prefix} Member not found. Attempting force join.")
    join_url = f"https://discord.com/api/v10/guilds/{guild.id}/members/{user_id}"
    join_headers = {"Authorization": f"Bot {BOT_TOKEN}", "Content-Type": "application/json"}
    join_payload = {"access_token": access_token}
    updated_member = None
    last_exception = None

    for attempt in range(MAX_API_ATTEMPTS):
        try:
            await asyncio.sleep(API_CALL_DELAY_SECONDS * (attempt + 1))
            logging.debug(f"{log_prefix} Sending PUT request to {join_url} for force join (Attempt {attempt + 1}/{MAX_API_ATTEMPTS}).")
            async with bot.http_session.put(join_url, json=join_payload, headers=join_headers, timeout=20) as response:
                if response.status in [201, 204]:
                    logging.info(f"{log_prefix} Force join request successful (status {response.status}) on attempt {attempt + 1}. Fetching member again.")
                    await asyncio.sleep(2)
                    # 멤버 재획득 시도 (내부적으로 재시도 포함)
                    updated_member = await _get_or_fetch_member(guild, user_id_int, f"{log_prefix} [Post-Join Fetch]")

                    if updated_member:
                        logging.info(f"{log_prefix} Adding role after successful join.")
                        # 역할 부여 시도 (내부적으로 재시도 포함)
                        role_add_code = await _manage_user_role(updated_member, role, "add", "Joined via Token Check & Role Add", log_prefix)
                        if role_add_code == '1' or role_add_code == '0':
                            return '1', updated_member # 최종 성공
                        else:
                            logging.error(f"{log_prefix} Failed to add role after force join (code: {role_add_code}).")
                            return '2', updated_member # 역할 추가 실패
                    else:
                        logging.error(f"{log_prefix} Failed to fetch member object even after successful join response.")
                        return '2', None # 멤버 재획득 실패

                # 클라이언트 오류 (4xx) 는 재시도하지 않음
                elif 400 <= response.status < 500:
                    error_text = await response.text()
                    logging.error(f"{log_prefix} Force join failed with client error {response.status} on attempt {attempt + 1}. No retry. Response: {error_text[:200]}")
                    last_exception = aiohttp.ClientResponseError(response.request_info, response.history, status=response.status, message=error_text)
                    break # 루프 종료
                else: # 5xx 또는 기타 오류
                    error_text = await response.text()
                    logging.warning(f"{log_prefix} Force join failed with status {response.status} on attempt {attempt + 1}. Response: {error_text[:200]}")
                    last_exception = aiohttp.ClientResponseError(response.request_info, response.history, status=response.status, message=error_text)
            # 5xx 오류 시 재시도 로직으로 넘어감

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logging.warning(f"{log_prefix} Network error during force join on attempt {attempt + 1}: {type(e).__name__}")
            last_exception = e
            # 네트워크 오류는 재시도
        except Exception as join_e:
            logging.error(f"{log_prefix} Unexpected exception during force join on attempt {attempt + 1}: {join_e}", exc_info=True)
            last_exception = join_e
            break # 예상 못한 오류는 재시도 안 함

        # 마지막 시도가 아니면 재시도
        if attempt < MAX_API_ATTEMPTS - 1:
            logging.info(f"{log_prefix} Retrying force join in {RETRY_DELAY_SECONDS} seconds...")
            await asyncio.sleep(RETRY_DELAY_SECONDS)
        else:
            logging.error(f"{log_prefix} Force join failed after {MAX_API_ATTEMPTS} attempts. Last error: {last_exception}")

    return '2', updated_member

async def process_single_user(
    guild: discord.Guild,
    user_id: str,
    role: Optional[discord.Role],
    current_check_timestamp: int,
    semaphore: asyncio.Semaphore,
    determined_user_status: str,
    current_access_token: Optional[str]
) -> Dict[str, Any]:
    async with semaphore:
        user_id_str = str(user_id)
        result = {
            "user_id": user_id_str, "guild_id": str(guild.id), "guild_name": guild.name,
            "final_status": determined_user_status,
            "role_action_code": '0',
            "message_code": "??",
            "detail": ""
        }
        try:
            if not role:
                result["role_action_code"] = '9'
                result["detail"] = "역할 객체 없음"
            else:
                try:
                    user_id_int = int(user_id_str)
                except ValueError:
                    result.update({"role_action_code": '9', "detail": "잘못된 사용자 ID"})
                    result["message_code"] = f"?{result['role_action_code']}"
                    return result

                member = await _get_or_fetch_member(guild, user_id_int, f"[AutoCheck {user_id}]")

                if determined_user_status == 'O':
                    if member:
                        result["role_action_code"] = await _manage_user_role(member, role, "add", "AutoCheck: Token valid", f"[AutoCheck {user_id}]")
                    elif current_access_token:
                        role_code, _ = await _attempt_force_join_and_role(guild, user_id_str, user_id_int, role, current_access_token, f"[AutoCheck {user_id}]")
                        result["role_action_code"] = role_code
                        result["detail"] += f" (강제 가입 시도: {role_code})"
                    else:
                        result["role_action_code"] = '9'
                        result["detail"] += " (멤버 없고 토큰 갱신 실패로 강제 가입 불가)"
                else: # determined_user_status == 'X'
                    if member:
                        result["role_action_code"] = await _manage_user_role(member, role, "remove", "AutoCheck: Token invalid", f"[AutoCheck {user_id}]")
                    else:
                        result["role_action_code"] = '0'

            result["message_code"] = f"?{result['role_action_code']}" # Wrapper에서 토큰 코드와 합쳐짐
            return result
        except Exception as e:
            logging.error(f"[AutoCheck {user_id_str} Guild {guild.id}] Exception in process_single_user (post-token check): {e}", exc_info=True)
            result.update({
                "role_action_code": '9',
                "message_code": "?9",
                "detail": f"길드 처리 중 예외: {type(e).__name__}"
            })
            return result

async def check_user(interaction: discord.Interaction, user_id: str):
    """
    [일반 관리자용] 특정 사용자의 정보를 DB에서 조회하여 표시합니다.
    사용자가 DB에 존재하고 상태(status)가 'O'이며, **현재 서버 설정에도 등록된 경우**에만 정보를 표시합니다.
    """
    log_prefix = f"[CheckUser(Admin) User {user_id} Guild {interaction.guild_id}]" # 길드 ID 포함
    logging.info(f"{log_prefix} Initiating user info lookup (Status 'O' and Guild Config required).")
    user_id_str = str(user_id)

    followup = interaction.followup
    edit_original = interaction.edit_original_response

    try:
        # 상호작용 처리 (기존과 동일)
        if interaction.response.is_done():
             logging.warning(f"{log_prefix} Interaction already responded to.")
             return
        logging.debug(f"{log_prefix} Deferring interaction response.")
        try: await interaction.response.defer(ephemeral=True, thinking=True)
        except discord.InteractionResponded: logging.warning(f"{log_prefix} Defer failed, interaction already responded.")
        except Exception as defer_e:
            logging.error(f"{log_prefix} Defer interaction failed: {defer_e}", exc_info=True)
            try: await followup.send("명령 처리 시작 중 오류가 발생했습니다.", ephemeral=True)
            except Exception: pass
            return

        # 설정 로드 및 길드 확인
        guild_id = str(interaction.guild_id) if interaction.guild_id else None
        if not guild_id:
             logging.error(f"{log_prefix} Guild ID not found.")
             await edit_original(content="길드 정보를 찾을 수 없습니다.", view=None, embed=None)
             return

        guild_config = None
        config_users = set()
        try:
            # load_config 와 read_user_data_db 함수는 이 함수 외부에 정의되어 있다고 가정
            config_data = await asyncio.to_thread(load_config)
            guild_config = config_data.get(guild_id)
            if guild_config and isinstance(guild_config, dict):
                # 현재 길드의 설정 파일 사용자 목록 로드
                config_users = {str(u) for u in guild_config.get("users", [])}
            else:
                 logging.info(f"{log_prefix} Guild {guild_id} config not found or invalid.")
                 await edit_original(content="등록되지 않은 서버입니다.", view=None, embed=None)
                 return
        except Exception as e:
             logging.error(f"{log_prefix} Failed to load config: {e}", exc_info=True)
             await edit_original(content="설정 파일을 로드하는 중 오류가 발생했습니다.", view=None, embed=None)
             return

        # 사용자 데이터 로드 (DB 사용)
        user_data = await read_user_data_db(user_id_str) # 이 함수도 외부에 정의되어 있다고 가정

        # --- 핵심 변경점: DB 상태('O') 및 현재 길드 설정 파일 포함 여부 동시 확인 ---
        is_verified_in_this_guild = False
        if user_data and user_data.get("status") == 'O' and user_id_str in config_users:
            is_verified_in_this_guild = True

        if not is_verified_in_this_guild:
            # DB에 없거나, 상태가 'X'거나, 이 길드 설정에 사용자가 없는 경우
            logging.info(f"{log_prefix} User {user_id_str} check failed: DB Data={bool(user_data)}, Status={user_data.get('status') if user_data else 'N/A'}, InGuildConfig={user_id_str in config_users}")
            message = f"🚫 사용자 `{user_id_str}` 정보를 찾을 수 없거나 이 서버에서 인증된 상태가 아닙니다."

            # 상세 원인 로깅 (선택적)
            if not user_data: logging.info(f"{log_prefix} Reason: User not found in DB.")
            elif user_data.get("status") != 'O': logging.info(f"{log_prefix} Reason: User status in DB is '{user_data.get('status')}'.")
            elif user_id_str not in config_users: logging.info(f"{log_prefix} Reason: User not found in this guild's config file.")

            await edit_original(content=message, view=None, embed=None)
            return

        # 사용자 정보 파싱
        user_email = str(user_data.get("email", "이메일 없음"))
        user_ip = str(user_data.get("ip", "IP 없음")) # IP 자체는 여전히 필요할 수 있음
        user_agent = str(user_data.get("user_agent", "User-Agent 없음"))
        auth_time = str(user_data.get("auth_time", "시간 정보 없음"))
        status = 'O'

        country = str(user_data.get("country", "정보 없음"))
        region = str(user_data.get("region", "정보 없음"))
        city = str(user_data.get("city", "정보 없음"))
        isp = str(user_data.get("isp", "정보 없음"))

        # User-Agent 파싱
        device, os_info, browser_info = "정보 없음", "정보 없음", "정보 없음"
        if user_agent != "User-Agent 없음":
             try:
                 # parse 함수는 외부에 정의되어 있다고 가정 (from user_agents import parse)
                 ua = parse(user_agent)
                 os_family = ua.os.family if ua.os and ua.os.family else "Unknown"
                 device_map = { "Windows": "PC", "Mac OS X": "Mac", "Linux": "PC", "iOS": "Mobile (iOS)", "Android": "Mobile (Android)" }
                 device = device_map.get(os_family, "Unknown Device")
                 os_info = f"{ua.os.family or ''} {ua.os.version_string or ''}".strip() or "Unknown OS"
                 browser_info = f"{ua.browser.family or ''} {ua.browser.version_string or ''}".strip() or "Unknown Browser"
             except Exception as ua_e:
                 logging.error(f"{log_prefix} User-Agent 파싱 오류: {ua_e}")
                 device, os_info, browser_info = "파싱 오류", "파싱 오류", "파싱 오류"

        # 길드 멤버 정보 및 아바타 URL 가져오기
        guild = bot.get_guild(int(guild_id)) # bot 객체는 외부에 정의되어 있다고 가정
        member: Optional[discord.Member] = None
        username = f"{user_id_str} (정보 조회 불가)"
        avatar_url: Optional[str] = None
        if guild:
            try:
                # _get_or_fetch_member 함수는 외부에 정의되어 있다고 가정
                member = await _get_or_fetch_member(guild, int(user_id_str), log_prefix)
                if member:
                    display_name = member.global_name or member.nick or member.name
                    if member.discriminator == "0": username = f"{display_name} (@{member.name})"
                    else: username = f"{display_name} ({member.name}#{member.discriminator})"
                    avatar_url = member.display_avatar.url
                else: username = f"{user_id_str} (서버 멤버 아님)"
            except Exception as fetch_e:
                logging.error(f"{log_prefix} 멤버 정보 조회 중 오류: {fetch_e}", exc_info=True)
                username = f"{user_id_str} (멤버 정보 조회 오류)"

        embed_color = discord.Color.green()
        embed = discord.Embed(
            title="✅ 사용자 인증 정보 확인",
            # ... (description 등 동일) ...
        )
        # ... (thumbnail 등 동일) ...

        # --- ▼ Embed 필드 수정 (DB에서 읽은 값 사용) ▼ ---
        embed.add_field(name="🆔 사용자 ID", value=f"```{user_id_str}```", inline=True)
        embed.add_field(name="👤 디스코드 프로필", value=f"```{username}```", inline=True)
        embed.add_field(name="✅ 현재 인증 상태", value="```정상 (O)```", inline=True)

        embed.add_field(name="📧 이메일", value=f"```{user_email}```", inline=True)
        embed.add_field(name="⏰ 마지막 인증 시간", value=f"```{auth_time}```", inline=True)
        embed.add_field(name="\u200B", value="\u200B", inline=True)

        embed.add_field(name="🌍 IP 주소", value=f"```{user_ip}```", inline=True) # IP 자체는 보여줄 수 있음
        embed.add_field(name="🌐 국가", value=f"```{country}```", inline=True) # 저장된 값 사용
        embed.add_field(name="🏙 지역", value=f"```{region} / {city}```", inline=True) # 저장된 값 사용

        embed.add_field(name="🏢 통신사 (ISP)", value=f"```{isp}```", inline=False) # 저장된 값 사용

        embed.add_field(name="📱 접속 기기", value=f"```{device}```", inline=True)
        embed.add_field(name="💻 운영체제", value=f"```{os_info}```", inline=True)
        embed.add_field(name="🌐 브라우저", value=f"```{browser_info}```", inline=True)

        embed.add_field(name="📜 User-Agent", value=f"```{user_agent}```", inline=False)
        # --- ▲ Embed 필드 수정 ▲ ---

        # 복사 가능한 텍스트 필드 (위치 정보도 포함되도록 업데이트)
        copy_text_lines = []
        for field in embed.fields:
            if field.name != '\u200B' and field.value != '\u200B':
                 field_value = field.value.replace('```', '').strip()
                 copy_text_lines.append(f"{field.name}: {field_value}")
        copy_text = "\n".join(copy_text_lines)
        max_copy_len = 1024 - 10
        copy_text_display = copy_text[:max_copy_len - 3] + "..." if len(copy_text) > max_copy_len else copy_text
        embed.add_field( name="📋 복사 가능한 텍스트", value=f"```{copy_text_display}```", inline=False)

        embed.set_footer(text="DB 정보, 서버 설정(sync_config.json), Discord 프로필 기반")

        # 최종 메시지 전송/수정
        logging.debug(f"{log_prefix} Sending final response.")
        try:
            await edit_original(content=None, embed=embed, view=None)
            logging.info(f"{log_prefix} Successfully displayed user info for {user_id_str}.")
        except Exception as e:
            logging.error(f"{log_prefix} Failed to edit original response: {e}", exc_info=True)
            # Followup은 이미 defer에서 에러났을 경우 추가 에러 발생 가능성 있음
            try: await followup.send(embed=embed, ephemeral=True)
            except Exception as final_followup_e: logging.error(f"{log_prefix} Final followup send also failed: {final_followup_e}")

    except Exception as e: # 함수 최상위 예외 처리
        logging.critical(f"{log_prefix} check_user failed with top-level error: {e}", exc_info=True)
        error_message = "사용자 정보 조회 중 예상치 못한 오류가 발생했습니다."
        try:
             # 응답을 이미 보냈거나 defer 실패했을 수 있으므로 안전하게 처리
             if interaction and not interaction.is_expired():
                 # edit_original_response는 defer 성공 시에만 가능
                 # is_done()으로 확인하거나, 그냥 followup 사용
                 if interaction.response.is_done():
                      await interaction.followup.send(error_message, ephemeral=True)
                 else:
                      # defer 실패 등의 이유로 is_done()이 False일 수 있음
                      # 이 경우 edit_original 시도 시 에러 발생 가능
                      # 안전하게 followup 사용 고려 또는 추가적인 is_done() 상태 체크
                      try: await interaction.edit_original_response(content=error_message, view=None, embed=None)
                      except discord.InteractionResponded: # 혹시 모를 경쟁 상태
                           await interaction.followup.send(error_message, ephemeral=True)
                      except Exception as edit_err: # 기타 edit 에러
                          logging.error(f"{log_prefix} Failed to send error via edit_original: {edit_err}")
                          await interaction.followup.send(error_message, ephemeral=True) # 최종적으로 followup 시도
        except Exception as resp_e:
             logging.error(f"{log_prefix} Failed to send error response in top-level handler: {resp_e}")

async def super_check_user(interaction: discord.Interaction, user_id: str):
    """
    [총괄 관리자용] 특정 사용자의 정보를 DB에서 조회하여 표시합니다.
    DB에 사용자 ID가 존재하면 상태(status)에 상관없이 모든 정보를 표시합니다.
    설정 파일 기준 참가 서버 ID 목록을 포함합니다.
    """
    log_prefix = f"[SuperCheckUser User {user_id}]"
    logging.info(f"{log_prefix} Initiating DB user info lookup (any status).")
    user_id_str = str(user_id)

    followup = interaction.followup
    edit_original = interaction.edit_original_response

    try:
        # 상호작용 처리 (기존과 동일)
        if interaction.response.is_done():
             logging.warning(f"{log_prefix} Interaction already responded to.")
             return
        logging.debug(f"{log_prefix} Deferring interaction response.")
        try: await interaction.response.defer(ephemeral=True, thinking=True)
        except discord.InteractionResponded: logging.warning(f"{log_prefix} Defer failed, interaction already responded.")
        except Exception as defer_e:
            logging.error(f"{log_prefix} Defer interaction failed: {defer_e}", exc_info=True)
            try: await followup.send("명령 처리 시작 중 오류가 발생했습니다.", ephemeral=True)
            except Exception: pass
            return

        guild_id = str(interaction.guild_id) if interaction.guild_id else None
        logging.debug(f"{log_prefix} Invoked from guild context: {guild_id}")

        # 사용자 데이터 로드 (DB 사용)
        user_data = await read_user_data_db(user_id_str)

        if not user_data:
            logging.warning(f"{log_prefix} User {user_id_str} not found in DB.")
            message = f"🚫 사용자 `{user_id_str}` 정보를 DB에서 찾을 수 없습니다."
            await edit_original(content=message, view=None, embed=None)
            return

        user_email = str(user_data.get("email", "이메일 없음"))
        user_ip = str(user_data.get("ip", "IP 없음")) # IP 자체는 보여줌
        user_agent = str(user_data.get("user_agent", "User-Agent 없음"))
        auth_time = str(user_data.get("auth_time", "시간 정보 없음"))
        status = str(user_data.get("status", "X"))
        # --- ▼ 저장된 위치 정보 사용 ▼ ---
        country = str(user_data.get("country", "정보 없음"))
        region = str(user_data.get("region", "정보 없음"))
        city = str(user_data.get("city", "정보 없음"))
        isp = str(user_data.get("isp", "정보 없음"))

        # --- 참가 서버 ID 목록 조회 로직 추가 ---
        associated_guild_ids = []
        config_load_error = False
        try:
            # 매번 최신 설정을 읽어옴
            config_data = await asyncio.to_thread(load_config)
            if isinstance(config_data, dict):
                for gid, gconf in config_data.items():
                    users_in_guild = gconf.get("users", [])
                    # users 값이 리스트나 집합 형태이고, 사용자가 포함되어 있는지 확인
                    if isinstance(users_in_guild, (list, set)) and user_id_str in users_in_guild:
                         associated_guild_ids.append(gid)
            else:
                 config_load_error = True
                 logging.error(f"{log_prefix} Failed to load or parse config data correctly.")
        except Exception as config_e:
            config_load_error = True
            logging.error(f"{log_prefix} Error loading config file: {config_e}", exc_info=True)

        # 참가 서버 ID 목록 포맷팅
        guild_list_value = "```\n해당 없음\n```"
        if config_load_error:
            guild_list_value = "```설정 파일 오류```"
        elif associated_guild_ids:
            # ID 목록 정렬
            sorted_guild_ids = sorted(associated_guild_ids)
            guild_list_str = "\n".join(sorted_guild_ids)
            # Embed 필드 길이 제한 (1024) 고려
            max_guild_list_len = 1024 - 10 # 코드 블록 문자 및 줄임표(...) 여유 공간
            if len(guild_list_str) > max_guild_list_len:
                guild_list_display = guild_list_str[:max_guild_list_len] + "\n..."
            else:
                guild_list_display = guild_list_str
            guild_list_value = f"```\n{guild_list_display}\n```"
        # --- 참가 서버 ID 로직 끝 ---

        # User-Agent 파싱 (기존과 동일)
        # ... (생략) ...
        device, os_info, browser_info = "정보 없음", "정보 없음", "정보 없음"
        if user_agent != "User-Agent 없음":
            try:
                ua = parse(user_agent)
                os_family = ua.os.family if ua.os and ua.os.family else "Unknown"
                device_map = { "Windows": "PC", "Mac OS X": "Mac", "Linux": "PC", "iOS": "Mobile (iOS)", "Android": "Mobile (Android)" }
                device = device_map.get(os_family, "Unknown Device")
                os_info = f"{ua.os.family or ''} {ua.os.version_string or ''}".strip() or "Unknown OS"
                browser_info = f"{ua.browser.family or ''} {ua.browser.version_string or ''}".strip() or "Unknown Browser"
            except Exception as ua_e:
                logging.error(f"{log_prefix} User-Agent 파싱 오류: {ua_e}")
                device, os_info, browser_info = "파싱 오류", "파싱 오류", "파싱 오류"

        # 사용자 프로필 정보 조회 (기존과 동일)
        # ... (생략) ...
        username = f"{user_id_str}"
        avatar_url: Optional[str] = None
        try:
             user_obj = await bot.fetch_user(int(user_id_str))
             if user_obj:
                  if user_obj.discriminator == "0": username = f"{user_obj.global_name or user_obj.name} (@{user_obj.name})"
                  else: username = f"{user_obj.name}#{user_obj.discriminator}"
                  avatar_url = user_obj.display_avatar.url
        except discord.NotFound: username = f"{user_id_str} (사용자 정보 조회 불가)"
        except Exception as fetch_e:
             logging.error(f"{log_prefix} 사용자({user_id_str}) 정보 조회 중 오류: {fetch_e}", exc_info=True)
             username = f"{user_id_str} (사용자 정보 조회 오류)"

        embed_color = discord.Color.green() if status == "O" else discord.Color.red()
        embed = discord.Embed(
            title="[총괄] DB 사용자 정보 조회",
            # ... (description 등 동일) ...
        )
        # ... (thumbnail 등 동일) ...

        # --- ▼ Embed 필드 수정 (DB에서 읽은 값 사용) ▼ ---
        embed.add_field(name="🆔 사용자 ID", value=f"```{user_id_str}```", inline=True)
        embed.add_field(name="👤 디스코드 프로필", value=f"```{username}```", inline=True)
        embed.add_field(name="✅ 저장된 인증 상태", value=f"```{'정상 (O)' if status == 'O' else '해제/만료 (X)'}```", inline=True)

        embed.add_field(name="📧 이메일", value=f"```{user_email}```", inline=True)
        embed.add_field(name="⏰ 마지막 인증 시간", value=f"```{auth_time}```", inline=True)
        embed.add_field(name="📚 참가 중인 서버 ID (설정 기준)", value=guild_list_value, inline=False)

        embed.add_field(name="🌍 IP 주소", value=f"```{user_ip}```", inline=True)
        embed.add_field(name="🌐 국가", value=f"```{country}```", inline=True) # 저장된 값 사용
        embed.add_field(name="🏙 지역", value=f"```{region} / {city}```", inline=True) # 저장된 값 사용

        embed.add_field(name="🏢 통신사 (ISP)", value=f"```{isp}```", inline=False) # 저장된 값 사용

        embed.add_field(name="📱 접속 기기", value=f"```{device}```", inline=True)
        embed.add_field(name="💻 운영체제", value=f"```{os_info}```", inline=True)
        embed.add_field(name="🌐 브라우저", value=f"```{browser_info}```", inline=True)

        embed.add_field(name="📜 User-Agent", value=f"```{user_agent}```", inline=False)
        # --- ▲ Embed 필드 수정 ▲ ---

        # 복사 가능한 텍스트 필드 (위치 정보 포함 업데이트)
        copy_text_lines = []
        for field in embed.fields:
            if field.name != '\u200B' and field.value != '\u200B':
                 field_value = field.value.replace('```', '').strip()
                 copy_text_lines.append(f"{field.name}: {field_value}")
        copy_text = "\n".join(copy_text_lines)
        max_copy_len = 1024 - 10
        copy_text_display = copy_text[:max_copy_len - 3] + "..." if len(copy_text) > max_copy_len else copy_text
        embed.add_field( name="📋 복사 가능한 텍스트", value=f"```{copy_text_display}```", inline=False)

        embed.set_footer(text="users.db, sync_config.json, Discord 사용자 정보 기반")

        # 최종 메시지 전송/수정 (기존과 동일)
        logging.debug(f"{log_prefix} Sending final response.")
        try:
            await edit_original(content=None, embed=embed, view=None)
            logging.info(f"{log_prefix} Successfully displayed DB user info for {user_id_str}.")
        except Exception as e:
            logging.error(f"{log_prefix} Failed to edit original response: {e}", exc_info=True)
            try: await followup.send(embed=embed, ephemeral=True)
            except Exception as final_followup_e: logging.error(f"{log_prefix} Final followup send also failed: {final_followup_e}")

    except Exception as e: # 함수 최상위 예외 처리 (기존과 동일)
        logging.critical(f"{log_prefix} super_check_user failed with top-level error: {e}", exc_info=True)
        error_message = "DB 사용자 정보 조회 중 예상치 못한 오류가 발생했습니다."
        try:
             if interaction and not interaction.is_expired() and not interaction.response.is_done():
                 await interaction.edit_original_response(content=error_message, view=None, embed=None)
             elif interaction and not interaction.is_expired():
                  await interaction.followup.send(error_message, ephemeral=True)
        except Exception: pass

async def _assign_role_to_user(guild: discord.Guild, user_id: str) -> bool:
    """Assigns role using helpers. Tries force join if member not found."""
    log_prefix = f"[AssignRole {user_id} Guild {guild.id}]"
    logging.info(f"{log_prefix} Role assignment attempt started via webhook.")
    user_id_str = str(user_id)
    guild_id_str = str(guild.id)

    guild_conf = guild_configs.get(guild_id_str)
    if not guild_conf or "role_id" not in guild_conf:
        logging.error(f"{log_prefix} Guild config or role ID not found in memory cache.")
        return False # Fail if config not cached

    role_id = guild_conf["role_id"]
    role = guild.get_role(role_id)
    if not role:
        logging.error(f"{log_prefix} Role ID {role_id} not found in guild {guild.name}.")
        return False

    try: user_id_int = int(user_id_str)
    except ValueError:
        logging.error(f"{log_prefix} Invalid user ID format.")
        return False

    # Use the helper to get/fetch member
    member = await _get_or_fetch_member(guild, user_id_int, log_prefix + " [Assign]")

    if not member:
        logging.warning(f"{log_prefix} Member not found in guild. Attempting force join.")
        # Need access token from DB for force join
        user_data = await read_user_data_db(user_id_str) # Fetch data (includes token)
        access_token = user_data.get("access_token") if user_data else None # Token is decrypted here

        if not access_token:
            logging.error(f"{log_prefix} Cannot force join: Access Token not found in DB for user {user_id_str}.")
            return False

        # Use the force join helper function
        role_add_code, member_after_join = await _attempt_force_join_and_role(
            guild, user_id_str, user_id_int, role, access_token, log_prefix
        )
        # Check if join and role assignment were successful
        # '0' for role code means already present (which is success in this context)
        # '1' means added successfully
        if member_after_join and (role_add_code == '1' or role_add_code == '0'):
             logging.info(f"{log_prefix} Force join and role assignment successful (Code: {role_add_code}).")
             return True
        else:
             logging.error(f"{log_prefix} Force join or subsequent role assignment failed (Code: {role_add_code}). Member obj: {bool(member_after_join)}")
             return False
    else:
        # Member found, manage role directly
        logging.info(f"{log_prefix} Member found. Managing role.")
        role_add_code = await _manage_user_role(member, role, "add", "Verified via Webhook/Assign Role", log_prefix)
        if role_add_code == '1' or role_add_code == '0':
            logging.info(f"{log_prefix} Role management successful (Code: {role_add_code}).")
            return True
        else:
            logging.error(f"{log_prefix} Role management failed (Code: {role_add_code}).")
            return False

async def _verify_webhook_signature(request: web.Request) -> Tuple[bool, Optional[bytes]]:
    """Verifies HMAC signature from request headers against the raw body."""
    timestamp_str = request.headers.get('X-Webhook-Timestamp')
    nonce = request.headers.get('X-Webhook-Nonce')
    received_sig_hex = request.headers.get('X-Webhook-Signature')

    if not all([timestamp_str, nonce, received_sig_hex]):
        logging.warning("Webhook: Missing signature headers.")
        return False, None

    try:
        timestamp = float(timestamp_str)
    except ValueError:
        logging.warning(f"Webhook: Invalid timestamp format: {timestamp_str}")
        return False, None

    # Validate timestamp (e.g., within 5 minutes)
    current_time = time.time()
    time_difference = abs(current_time - timestamp)
    if time_difference > 300: # 5 minutes tolerance
        logging.warning(f"Webhook: Timestamp validation failed. Difference: {time_difference:.2f}s")
        return False, None

    try:
        raw_body = await request.read() # Read the raw body *once*
        if not raw_body:
             logging.warning("Webhook: Request body is empty, cannot verify signature.")
             return False, None # Cannot verify empty body

        # Construct the message string exactly as the sender did
        message_string = f"{timestamp_str}:{nonce}:{raw_body.decode('utf-8')}"
        message_bytes = message_string.encode('utf-8')
        secret_bytes = WEBHOOK_AUTH_SECRET.encode('utf-8') # Ensure secret is bytes

        # Generate the expected signature
        expected_sig = hmac.new(secret_bytes, message_bytes, hashlib.sha256)
        expected_sig_hex = expected_sig.hexdigest()

        # Compare using hmac.compare_digest for timing attack resistance
        if hmac.compare_digest(expected_sig_hex, received_sig_hex):
            logging.debug("Webhook: HMAC signature verified successfully.")
            return True, raw_body # Return raw body if verification succeeds
        else:
            logging.warning("Webhook: Invalid HMAC signature.")
            # Log received vs expected for debugging (be careful with secrets)
            # logging.debug(f"Received Sig: {received_sig_hex}")
            # logging.debug(f"Expected Sig: {expected_sig_hex}")
            return False, None

    except Exception as e:
        logging.error(f"Webhook: Error during signature verification: {e}", exc_info=True)
        return False, None

async def handle_verification_webhook(request: web.Request):
    is_valid_signature, raw_body = await _verify_webhook_signature(request)
    if not is_valid_signature:
        return web.Response(status=403, text="Forbidden: Invalid Signature")

    payload: Optional[Dict[str, Any]] = None
    payload_str: Optional[str] = None
    user_id: Optional[str] = None
    guild_id: Optional[str] = None
    verification_type: Optional[str] = None

    try:
        payload_str = raw_body.decode('utf-8')
        payload = json.loads(payload_str)

        # --- ★★★ 입력값 검증 강화 ★★★ ---
        user_id = payload.get('user_id')
        guild_id = payload.get('guild_id')
        encrypted_data_str = payload.get('encrypted_data')
        verification_type = payload.get('verification_type', 'single') # 기본값 'single'

        if not user_id or not isinstance(user_id, str) or not user_id.isdigit() or not (17 <= len(user_id) <= 20):
            raise ValueError(f"Invalid user_id format or length: {user_id}")
        if not guild_id or not isinstance(guild_id, str) or not guild_id.isdigit() or not (17 <= len(guild_id) <= 20):
            raise ValueError(f"Invalid guild_id format or length: {guild_id}")
        if not encrypted_data_str or not isinstance(encrypted_data_str, str):
             raise ValueError("Missing or invalid 'encrypted_data' field")
        if verification_type not in ['single', 'multi_reverify']:
             raise ValueError(f"Invalid 'verification_type': {verification_type}")
        # --- ★★★ 검증 끝 ★★★ ---

        logging.info(f"[Webhook-Handler User: {user_id} Guild: {guild_id}] Received and validated signature & basic payload.")
        asyncio.create_task(_process_verification_background(payload))
        logging.debug(f"[Webhook-Handler User: {user_id} Guild: {guild_id}] Background task created. Sending 200 OK response.")
        return web.Response(status=200, text="OK: Request received, processing in background.")

    except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e: # ValueError 추가
        log_prefix_err = f"[Webhook-Handler User: {user_id or 'N/A'} Guild: {guild_id or 'N/A'}]"
        logging.error(f"{log_prefix_err} Bad Request after signature validation - {e}. Payload: {payload_str[:500] if payload_str else 'N/A'}...")
        return web.Response(status=400, text=f"Bad Request: Invalid JSON or missing/invalid fields ({e})")
    except Exception as e:
        log_prefix_err = f"[Webhook-Handler User: {user_id or 'N/A'} Guild: {guild_id or 'N/A'}]"
        logging.error(f"{log_prefix_err} Unexpected error in handler: {e}", exc_info=True)
        return web.Response(status=500, text="Internal Server Error during request handling")
       
async def _process_verification_background(payload: Dict[str, Any]):
    user_id: Optional[str] = None
    guild_id: Optional[str] = None
    log_prefix = "[Webhook-BG]"
    is_suspicious_account = False

    try:
        user_id = str(payload['user_id'])
        guild_id = str(payload['guild_id'])
        encrypted_data_str = payload.get('encrypted_data')
        verification_type = payload.get('verification_type', 'single')
        log_prefix = f"[Webhook-BG User: {user_id} Guild: {guild_id}]"
        logging.info(f"{log_prefix} Starting background processing...")

        # --- 단계별 오류 처리 예시 ---
        try:
            decrypted_sensitive_data = decrypt_webhook_data(encrypted_data_str)
            if decrypted_sensitive_data is None: raise ValueError("Decryption failed")
        except (InvalidToken, ValueError, Exception) as e:
            logging.error(f"{log_prefix} Failed to decrypt data: {e}", exc_info=True)
            return # 복호화 실패 시 중단

        guild_object = bot.get_guild(int(guild_id))
        if not guild_object:
            logging.warning(f"{log_prefix} Guild object not found in background for ID {guild_id}.")
            return

        ip_address = decrypted_sensitive_data.get("ip")
        location_info = {"country": "정보 없음", "region": "정보 없음", "city": "정보 없음", "isp": "정보 없음"}
        if ip_address:
            try:
                 location_info = await _get_location_info_async(ip_address) # 재시도 로직 포함된 함수 호출
                 logging.debug(f"{log_prefix} Location fetched in background: {location_info}")
            except Exception as e: # _get_location_info_async 내부에서 처리되지만 최종 방어
                 logging.error(f"{log_prefix} Error fetching location: {e}", exc_info=True)
                 location_info = {"country": "오류", "region": "오류", "city": "오류", "isp": "오류"}
        else:
            logging.warning(f"{log_prefix} No IP address found in background data.")

        try:
            account_creation_dt_utc = discord.utils.snowflake_time(int(user_id))
            account_creation_dt_local_naive = account_creation_dt_utc.astimezone().replace(tzinfo=None)
            now_local_naive = datetime.now()
            seven_days_ago_local_naive = now_local_naive - timedelta(days=7)
            if account_creation_dt_local_naive > seven_days_ago_local_naive:
                is_suspicious_account = True
                logging.info(f"{log_prefix} Account creation date (Local: {account_creation_dt_local_naive.strftime('%Y-%m-%d %H:%M')}) is within 7 days. Flagged as suspicious.")
            else:
                 logging.debug(f"{log_prefix} Account creation date (Local: {account_creation_dt_local_naive.strftime('%Y-%m-%d %H:%M')}) is older than 7 days.")
        except ValueError:
             logging.error(f"{log_prefix} Invalid user ID format for snowflake time extraction: {user_id}")
        except Exception as e_creation_check:
             logging.error(f"{log_prefix} Error checking account creation date: {e_creation_check}", exc_info=True)

        final_user_data = {
            "user_id": user_id,
            "guild_id": guild_id,
            **decrypted_sensitive_data,
            **location_info
        }

        try:
            update_ok = await add_or_update_user_db(final_user_data)
            if not update_ok: raise aiosqlite.Error("DB update returned False")
            logging.info(f"{log_prefix} DB updated successfully in background.")
        except aiosqlite.Error as e:
             logging.error(f"{log_prefix} DB update failed: {e}", exc_info=True)
             # DB 실패 시 어떻게 처리할지 결정 (예: 재시도 큐, 관리자 알림)
             return # 일단 중단

        config_updated = False
        user_was_in_this_guild_config_before = False
        try:
            async with CONFIG_LOCK:
                config_data = await asyncio.to_thread(load_config)
                guild_conf_before = config_data.get(guild_id)
                if guild_conf_before and isinstance(guild_conf_before.get("users"), list):
                    user_was_in_this_guild_config_before = str(user_id) in guild_conf_before["users"]

                if guild_id in config_data:
                    guild_conf = config_data[guild_id]
                    if "users" not in guild_conf or not isinstance(guild_conf.get("users"), list): guild_conf["users"] = []
                    user_id_str = str(user_id)
                    if user_id_str not in guild_conf["users"]:
                        users_set = set(str(u) for u in guild_conf["users"] if u)
                        users_set.add(user_id_str)
                        guild_conf["users"] = sorted(list(users_set))
                        save_success = await asyncio.to_thread(save_config, config_data)
                        if save_success:
                            config_updated = True
                            await asyncio.to_thread(sync_guild_configs)
                            logging.info(f"{log_prefix} Config ADDED/synced in background.")
                        else:
                            logging.error(f"{log_prefix} Failed to save config in background.")
                else:
                    logging.error(f"{log_prefix} Guild ID {guild_id} disappeared from config during background processing.")
        except asyncio.TimeoutError:
             logging.error(f"{log_prefix} Timeout acquiring config lock in background.")
        except Exception as e_cfg:
            logging.error(f"{log_prefix} Config update error in background: {e_cfg}", exc_info=True)
            # 설정 파일 오류는 계속 진행할 수 있음 (역할 부여 시도)

        try:
            assign_ok = await _assign_role_to_user(guild_object, user_id) # 재시도 로직 포함됨
            if not assign_ok:
                 logging.error(f"{log_prefix} Role assignment failed (check inner function logs).")
                 # 역할 부여 실패 시 처리
            else:
                 logging.info(f"{log_prefix} Role assignment successful/checked.")
                 await _send_post_verification_notifications(
                     user_id, guild_id, guild_object, final_user_data,
                     verification_type,
                     is_reverification=user_was_in_this_guild_config_before,
                     is_suspicious=is_suspicious_account
                 )
        except Exception as e:
             logging.error(f"{log_prefix} Error during role assignment phase: {e}", exc_info=True)

        logging.info(f"{log_prefix} Background processing finished.")

    except Exception as e: # 최상위 예외 캐치
        bg_log_prefix = f"[Webhook-BG User: {user_id or 'N/A'} Guild: {guild_id or 'N/A'}]"
        logging.critical(f"{bg_log_prefix} CRITICAL error during background processing: {e}", exc_info=True)
        
async def _send_post_verification_notifications(
    user_id: str,
    guild_id: str,
    guild_object: discord.Guild,
    final_user_data: Dict[str, Any],
    verification_type: str,
    is_reverification: bool,
    is_suspicious: bool
):
    log_prefix_notify = f"[Webhook-Notify User: {user_id} Guild: {guild_id}]"

    try:
        guild_conf = guild_configs.get(str(guild_id))
        if guild_conf and guild_conf.get("log_channel_id"):
            log_channel_id = guild_conf["log_channel_id"]
            log_channel = bot.get_channel(log_channel_id)

            if log_channel and isinstance(log_channel, discord.TextChannel):
                log_perms = log_channel.permissions_for(guild_object.me)
                if log_perms.send_messages and log_perms.embed_links:
                    log_user = None
                    username_for_log = f"ID: {user_id}"
                    avatar_url_for_log = None
                    account_creation_date_str = "알 수 없음"
                    try:
                        log_user = await bot.fetch_user(int(user_id))
                        if log_user:
                            if log_user.discriminator == "0": username_for_log = f"{log_user.global_name or log_user.name} (@{log_user.name})"
                            else: username_for_log = f"{log_user.name}#{log_user.discriminator}"
                            avatar_url_for_log = log_user.display_avatar.url
                            # --- ★★★ 계정 생성일 로컬 시간 변환 ★★★ ---
                            account_creation_dt_utc = discord.utils.snowflake_time(int(user_id))
                            account_creation_dt_local = account_creation_dt_utc.astimezone() # 서버 로컬 시간대로 변환
                            account_creation_date_str = account_creation_dt_local.strftime('%Y-%m-%d %H:%M') # 로컬 시간 포맷팅
                            # --- ★★★ 변환 끝 ★★★ ---
                    except Exception as fetch_err:
                         logging.error(f"{log_prefix_notify} Error fetching user for logging: {fetch_err}", exc_info=True)

                    ip_for_log = final_user_data.get("ip", "정보 없음")
                    country_for_log = final_user_data.get("country", "정보 없음")
                    # region_for_log = final_user_data.get("region", "정보 없음") # 로그 Embed 간결화 위해 제거 가능
                    # city_for_log = final_user_data.get("city", "정보 없음") # 로그 Embed 간결화 위해 제거 가능
                    isp_for_log = final_user_data.get("isp", "정보 없음")
                    ua_for_log = final_user_data.get("user_agent", "정보 없음")
                    auth_time_for_log = final_user_data.get("auth_time", "정보 없음") # 이제 로컬 시간 문자열

                    embed_title = ""
                    embed_color = discord.Color.default()

                    if is_reverification:
                        embed_title = "🔄 사용자 재인증 로그"
                        embed_color = discord.Color.blue()
                    else:
                        embed_title = "✅ 신규 사용자 인증 로그"
                        embed_color = discord.Color.green()

                    if is_suspicious:
                        embed_color = discord.Color.orange()
                        embed_title += " (부계정 의심)"

                    # --- ★★★ Embed 타임스탬프도 로컬 시간으로 명시적 설정 ★★★ ---
                    log_embed = discord.Embed(title=embed_title, color=embed_color, timestamp=datetime.now()) # datetime.now()는 로컬 시간
                    if avatar_url_for_log: log_embed.set_thumbnail(url=avatar_url_for_log)
                    log_embed.add_field(name="사용자", value=f"{username_for_log}\n`{user_id}`", inline=True)
                    # --- ★★★ 필드명에서 (UTC) 제거 ★★★ ---
                    log_embed.add_field(name="인증 시간", value=f"`{auth_time_for_log}`", inline=True)
                    log_embed.add_field(name="계정 생성일", value=f"`{account_creation_date_str}`", inline=True)
                    log_embed.add_field(name="이메일", value=f"`{final_user_data.get('email', '정보 없음')}`", inline=True)
                    log_embed.add_field(name="IP 주소", value=f"`{ip_for_log}`", inline=True)
                    log_embed.add_field(name="국가", value=f"`{country_for_log}`", inline=True)
                    log_embed.add_field(name="ISP", value=f"`{isp_for_log}`", inline=True)
                    log_embed.add_field(name="User Agent", value=f"```\n{ua_for_log}\n```", inline=False)

                    if is_suspicious:
                        log_embed.add_field(
                            name="⚠️ 부계정 의심 정보",
                            value="```diff\n- 사유: 계정 생성 1주일 미만\n```",
                            inline=False
                        )

                    log_embed.set_footer(text=f"서버: {guild_object.name} ({guild_id})")

                    await log_channel.send(embed=log_embed)
                    log_type = "Re-verification" if is_reverification else "Initial verification"
                    logging.info(f"{log_prefix_notify} Sent log ({log_type}) to channel #{log_channel.name} ({log_channel_id}). Suspicious: {is_suspicious}")
                else:
                     logging.warning(f"{log_prefix_notify} Cannot send log to channel {log_channel_id}: Missing Send/Embed permission.")
    except Exception as e_log:
         logging.error(f"{log_prefix_notify} Error sending verification log: {e_log}", exc_info=True)

    # --- 사용자 DM 발송 로직 (기존과 동일) ---
    if verification_type == 'single':
        try:
            user = await bot.fetch_user(int(user_id))
            if user:
                guild_name = guild_object.name
                if is_reverification:
                    embed_title = "🔄 정보 갱신 완료"
                    embed_description = f"'{guild_name}' 서버의 인증 정보가 성공적으로 갱신되었습니다! (재인증)"
                    embed_color = discord.Color.blue()
                    log_message = f"{log_prefix_notify} Sent re-verification success DM."
                else:
                    embed_title = "✅ 인증 완료"
                    embed_description = f"'{guild_name}' 서버 인증이 성공적으로 완료되었습니다! (신규 인증)"
                    embed_color = discord.Color.green()
                    log_message = f"{log_prefix_notify} Sent initial verification success DM."

                embed = discord.Embed(title=embed_title, description=embed_description, color=embed_color)
                await user.send(embed=embed)
                logging.info(log_message)
            else:
                logging.warning(f"{log_prefix_notify} Could not find user {user_id} to send DM.")
        except discord.Forbidden:
            logging.warning(f"{log_prefix_notify} User {user_id} has DMs disabled or blocked the bot.")
        except Exception as e_dm:
            logging.error(f"{log_prefix_notify} Failed to send DM to user {user_id}: {e_dm}", exc_info=True)
    elif verification_type == 'multi_reverify':
        log_type = "Re-verification (Multi)" if is_reverification else "Initial verification (Multi? Unusual)"
        logging.info(f"{log_prefix_notify} {log_type}, skipping individual DM.")

async def handle_multi_reverify_complete(request: web.Request):
    log_prefix = "[Webhook-MultiComplete]"
    is_valid_signature, raw_body = await _verify_webhook_signature(request)
    if not is_valid_signature:
        return web.Response(status=403, text="Forbidden: Invalid Signature")

    user_id: Optional[str] = None
    original_dm_id: Optional[int] = None
    successful_guild_ids: Optional[List[str]] = None
    failed_guild_ids: Optional[List[str]] = None
    payload: Optional[Dict[str, Any]] = None
    payload_str: Optional[str] = None

    try:
        payload_str = raw_body.decode('utf-8')
        payload = json.loads(payload_str)

        user_id = payload.get('user_id')
        successful_guild_ids = payload.get('successful_guild_ids', [])
        failed_guild_ids = payload.get('failed_guild_ids', [])
        original_dm_id_raw = payload.get('original_dm_id')

        if not user_id or not isinstance(user_id, str) or not user_id.isdigit() or not (17 <= len(user_id) <= 20):
             raise ValueError(f"Invalid user_id format or length: {user_id}")

        if not isinstance(successful_guild_ids, list) or not all(isinstance(gid, str) and gid.isdigit() and (17 <= len(gid) <= 20) for gid in successful_guild_ids):
            raise ValueError(f"Invalid format or content for successful_guild_ids: {successful_guild_ids}")
        if not isinstance(failed_guild_ids, list) or not all(isinstance(gid, str) and gid.isdigit() and (17 <= len(gid) <= 20) for gid in failed_guild_ids):
             raise ValueError(f"Invalid format or content for failed_guild_ids: {failed_guild_ids}")

        if original_dm_id_raw is not None:
             if isinstance(original_dm_id_raw, int):
                 original_dm_id = original_dm_id_raw
             elif isinstance(original_dm_id_raw, str) and original_dm_id_raw.isdigit():
                 original_dm_id = int(original_dm_id_raw)
             else:
                  logging.warning(f"{log_prefix} Invalid 'original_dm_id' format received: {original_dm_id_raw}. Ignoring.")
                  original_dm_id = None

        logging.info(f"{log_prefix} (Verified) Received completion for User: {user_id}. Success: {len(successful_guild_ids)}, Failed: {len(failed_guild_ids)}, Parsed Original DM ID: {original_dm_id}")

    except (json.JSONDecodeError, KeyError, ValueError) as e:
        logging.error(f"{log_prefix} Bad Request after signature validation - {e}. Payload: {payload_str[:500] if payload_str else 'N/A'}...")
        return web.Response(status=400, text=f"Bad Request: Invalid JSON or missing/invalid fields ({e})")
    except Exception as e:
        logging.error(f"{log_prefix} Unexpected error during payload parsing after validation: {e}", exc_info=True)
        return web.Response(status=500, text="Internal Server Error during parsing")

    if original_dm_id and user_id:
        logging.info(f"{log_prefix} Valid original_dm_id ({original_dm_id}) and user_id ({user_id}) found. Proceeding with deletion attempt.")
        try:
            logging.debug(f"{log_prefix} Attempting to fetch user {user_id}...")
            user_obj_for_delete = await bot.fetch_user(int(user_id))

            if user_obj_for_delete:
                logging.debug(f"{log_prefix} User {user_id} fetched. Attempting to get/create DM channel...")
                dm_channel = user_obj_for_delete.dm_channel
                if not dm_channel:
                    logging.debug(f"{log_prefix} DM channel not cached for user {user_id}, creating...")
                    try:
                        dm_channel = await user_obj_for_delete.create_dm()
                    except discord.Forbidden:
                        logging.warning(f"{log_prefix} Forbidden to create DM channel for user {user_id}.")
                        dm_channel = None
                    except Exception as create_dm_e:
                        logging.error(f"{log_prefix} Error creating DM channel for user {user_id}: {create_dm_e}", exc_info=True)
                        dm_channel = None

                if dm_channel:
                    logging.debug(f"{log_prefix} DM channel obtained (ID: {dm_channel.id}). Attempting to fetch message {original_dm_id}...")
                    try:
                        message_to_delete = await dm_channel.fetch_message(original_dm_id)
                        logging.debug(f"{log_prefix} Message {original_dm_id} fetched. Attempting delete...")
                        await message_to_delete.delete()
                        logging.info(f"{log_prefix} Successfully deleted original DM (ID: {original_dm_id}).")
                    except discord.NotFound:
                        logging.warning(f"{log_prefix} Original DM (ID: {original_dm_id}) not found when fetching. Already deleted?")
                    except discord.Forbidden:
                        logging.warning(f"{log_prefix} Forbidden to fetch/delete message {original_dm_id} in DM channel {dm_channel.id}.")
                    except discord.HTTPException as http_e:
                        logging.error(f"{log_prefix} HTTP error fetching/deleting message {original_dm_id}: {http_e.status} - {http_e.text}", exc_info=True)
                    except Exception as e_fetch_delete:
                        logging.error(f"{log_prefix} Unexpected error fetching/deleting message {original_dm_id}: {e_fetch_delete}", exc_info=True)
                else:
                     logging.warning(f"{log_prefix} Could not get or create DM channel for user {user_id} to delete message.")
            else:
                logging.warning(f"{log_prefix} Could not fetch user object for user {user_id} to initiate deletion.")
        except discord.NotFound:
             logging.warning(f"{log_prefix} Could not fetch user {user_id} (NotFound).")
        except discord.Forbidden:
             logging.warning(f"{log_prefix} Forbidden error occurred while fetching user or creating DM for user {user_id}.")
        except Exception as e_delete_outer:
            logging.error(f"{log_prefix} Outer error during deletion process for DM {original_dm_id} for user {user_id}: {e_delete_outer}", exc_info=True)
    elif user_id:
         logging.debug(f"{log_prefix} No valid original_dm_id found in payload for user {user_id}. Skipping deletion.")
    else:
         logging.error(f"{log_prefix} User ID missing in completion payload. Cannot proceed with deletion logic.")

    try:
        user = await bot.fetch_user(int(user_id))
        if not user:
            logging.warning(f"{log_prefix} User {user_id} fetch returned None, cannot send completion DM.")
            return web.Response(status=404, text="User not found")

        embed = discord.Embed(
            title="✅ 일괄 서버 재인증 결과",
            description="요청하신 여러 서버에 대한 재인증 처리가 완료되었습니다.",
            color=discord.Color.green(),
            timestamp=datetime.now()
        )
        embed.set_footer(text="개별 서버에서 역할이 정상적으로 부여/확인되었는지 확인해보세요.")

        if successful_guild_ids:
            success_names = []
            for gid in successful_guild_ids:
                guild = bot.get_guild(int(gid))
                success_names.append(guild.name if guild else f"서버 ID: {gid}")
            success_field_value = "```\n- " + "\n- ".join(sorted(success_names)) + "\n```"
            embed.add_field(name=f"✔️ 성공 ({len(successful_guild_ids)}개)", value=success_field_value, inline=False)
        else:
            embed.add_field(name="✔️ 성공", value="```\n성공적으로 처리된 서버가 없습니다.\n```", inline=False)

        if failed_guild_ids:
            fail_names = []
            for gid in failed_guild_ids:
                guild = bot.get_guild(int(gid))
                fail_names.append(guild.name if guild else f"서버 ID: {gid}")
            fail_field_value = ("```\n- " + "\n- ".join(sorted(fail_names)) + "\n```\n"
                                "*(참고: '실패'는 웹 서버에서 봇에게 정보 전달 중 문제 발생을 의미합니다. 잠시 후 다시 시도하거나 관리자에게 문의하세요.)*")
            embed.add_field(name=f"⚠️ 실패 ({len(failed_guild_ids)}개)", value=fail_field_value, inline=False)

        await user.send(embed=embed)
        logging.info(f"{log_prefix} Successfully sent consolidated completion DM to user {user_id}.")
        return web.Response(status=200, text="OK: Completion DM Sent")

    except discord.NotFound:
         logging.warning(f"{log_prefix} User {user_id} not found via fetch_user, cannot send completion DM.")
         return web.Response(status=404, text="User not found")
    except discord.Forbidden:
        logging.warning(f"{log_prefix} User {user_id} blocked DMs or the bot (completion DM).")
        return web.Response(status=403, text="DM Forbidden")
    except Exception as e:
        logging.error(f"{log_prefix} Failed to send consolidated completion DM to user {user_id}: {e}", exc_info=True)
        return web.Response(status=500, text="Internal Server Error sending DM")
                   
async def setup_webhook_server(client: commands.Bot):
    global webhook_server_running # 전역 변수 사용 선언
    if webhook_server_running: # 이미 실행 중이면 아무것도 안 함
        logging.info("Webhook server is already running. Skipping setup.")
        return

    app = web.Application()
    app.add_routes([
        web.post('/notify_verification', handle_verification_webhook),
        web.post('/notify_multi_reverify_complete', handle_multi_reverify_complete)
    ])
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', WEBHOOK_PORT)
    try:
        await site.start()
        logging.info(f"Webhook server started on 0.0.0.0:{WEBHOOK_PORT} ...")
        client.webhook_runner = runner
        webhook_server_running = True # 실행 상태 플래그 설정
    except Exception as e:
        logging.critical(f"Webhook 서버 시작 실패: {e}", exc_info=True) # exc_info=True 추가 권장
        # 여기서 바로 종료하지 않고, on_ready에서 처리하도록 함
        raise # 예외를 다시 발생시켜 on_ready에서 잡도록 함

async def cleanup_webhook_server(client: commands.Bot):
    global webhook_server_running
    if hasattr(client, 'webhook_runner'):
        await client.webhook_runner.cleanup()
        logging.info("Webhook server cleaned up.")
        webhook_server_running = False 

async def send_verification_message(guild_id: str):
    """지정된 길드의 인증 채널에 초기 인증 메시지(Embed + 버튼)를 보냅니다."""
    log_prefix = f"[SendVerifyMsg Guild {guild_id}]"
    logging.info(f"{log_prefix} Attempting to send initial verification message.")

    # 1. 길드 설정 가져오기 (메모리의 guild_configs 사용)
    # guild_configs 딕셔너리가 이 함수 범위에서 접근 가능해야 함
    guild_conf = guild_configs.get(str(guild_id))
    if not guild_conf:
        logging.error(f"{log_prefix} Guild config not found in memory.")
        return # 설정 없으면 함수 종료

    # 2. 인증 채널 ID 및 객체 가져오기
    verify_channel_id = guild_conf.get("verify_channel_id")
    if not verify_channel_id:
        logging.error(f"{log_prefix} Verification channel ID not found in config.")
        return

    # bot 객체가 이 함수 범위에서 접근 가능해야 함
    channel = bot.get_channel(verify_channel_id)
    if not channel or not isinstance(channel, discord.TextChannel):
        logging.error(f"{log_prefix} Verification channel (ID: {verify_channel_id}) not found or not a text channel.")
        return

    # 3. 봇 권한 확인 (메시지 보내기, 링크 첨부, 채널 정리(선택))
    guild = channel.guild # 채널 객체에서 길드 객체 가져오기
    if not guild:
         logging.error(f"{log_prefix} Could not get guild object from channel {channel.id}.")
         return # 길드 객체를 얻을 수 없으면 종료

    perms = channel.permissions_for(guild.me) # 해당 채널에서 봇(me)의 권한 확인
    if not perms.send_messages or not perms.embed_links:
        logging.error(f"{log_prefix} Missing Send Messages or Embed Links permission in channel {channel.id}.")
        # 권한 부족 시 관리자에게 알릴 방법 고려 (예: admin_channel에 메시지 보내기)
        return # 필수 권한 없으면 종료

    # 4. 채널 메시지 정리 (선택적)
    if perms.read_message_history and perms.manage_messages:
        try:
            logging.debug(f"{log_prefix} Purging messages in channel {channel.id}.")
            await channel.purge(limit=100) # 기존 메시지 삭제
        except discord.Forbidden:
            logging.warning(f"{log_prefix} Missing Manage Messages permission in channel {channel.id}. Skipping purge.")
        except Exception as purge_e:
            logging.error(f"{log_prefix} Error purging channel {channel.id}: {purge_e}", exc_info=True)
    else:
         logging.warning(f"{log_prefix} Missing Read History or Manage Messages permission. Skipping purge.")


    # 5. State 생성 및 서명
    signed_state = None
    try:
        state_data = {
            'guild_id': str(guild_id), # 문자열 ID 사용
            'nonce': os.urandom(16).hex()
        }
        # serializer 객체가 정의되어 있고 사용 가능해야 함
        signed_state = serializer.dumps(state_data)
        logging.debug(f"{log_prefix} Generated signed state.")
    except NameError:
        logging.error(f"{log_prefix} serializer is not defined! Cannot sign state.")
        return
    except Exception as sign_e:
        logging.error(f"{log_prefix} Failed to sign state: {sign_e}", exc_info=True)
        return

    # 6. 인증 링크 생성
    try:
        from urllib.parse import quote # URL 인코딩 함수 임포트
        # REDIRECT_URI, CLIENT_ID 변수가 정의되어 있어야 함
        redirect_uri_encoded = quote(REDIRECT_URI, safe='')
        auth_link = f"https://discord.com/oauth2/authorize?client_id={CLIENT_ID}&response_type=code&redirect_uri={redirect_uri_encoded}&scope=identify+email+guilds.join&state={signed_state}"
        logging.debug(f"{log_prefix} Generated auth link.")
    except NameError:
         logging.error(f"{log_prefix} CLIENT_ID or REDIRECT_URI is not defined!")
         return
    except ImportError:
         logging.error(f"{log_prefix} urllib.parse.quote is required but not imported!")
         return
    except Exception as link_e:
         logging.error(f"{log_prefix} Failed to generate auth link: {link_e}", exc_info=True)
         return

    # 7. Embed 및 View 생성
    embed = discord.Embed(title="🔒 인증 필요", description="서비스 이용을 위해 인증해주세요.", color=0x2563eb)
    embed.set_image(url="https://media.discordapp.net/attachments/1068698099108823060/1098916578852085821/31a72afda250825d993400c3ef28c55c.gif") # 이미지 URL 확인 필요

    view = discord.ui.View()
    view.add_item(discord.ui.Button(label="✅ 인증", style=discord.ButtonStyle.link, url=auth_link))

    # 8. 메시지 전송
    try:
        await channel.send(embed=embed, view=view)
        logging.info(f"{log_prefix} Verification message sent successfully to channel {channel.id}.")
    except discord.Forbidden:
        logging.error(f"{log_prefix} Forbidden to send message in channel {channel.id}.")
    except Exception as send_e:
        logging.error(f"{log_prefix} Failed to send verification message to channel {channel.id}: {send_e}", exc_info=True)

class ConfigChangeEventHandler(PatternMatchingEventHandler):
    """sync_config.json 파일 변경 감지 및 동기화 트리거 핸들러."""
    def __init__(self, loop: asyncio.AbstractEventLoop):
        # CONFIG_FILE 이름만 감지하도록 설정
        super().__init__(patterns=[CONFIG_FILE], ignore_directories=True, case_sensitive=False)
        self.loop = loop
        self._debounce_task: Optional[asyncio.Task] = None
        self._debounce_time = 2.0 # 2초 디바운스 (파일 저장 시 여러 이벤트 방지)

    async def _sync_task(self):
        """실제 동기화 작업을 수행하는 비동기 태스크 (스레드에서 실행)."""
        logging.info(f"Debounced change detected for {CONFIG_FILE}. Triggering sync...")
        try:
            # sync_guild_configs는 파일 I/O가 있으므로 스레드에서 실행
            await asyncio.to_thread(sync_guild_configs)
        except Exception as e:
            logging.error(f"Error during scheduled config sync initiated by watchdog: {e}", exc_info=True)

    def on_modified(self, event):
        """파일 수정 이벤트 발생 시 호출됩니다."""
        # 이벤트가 발생한 경로가 정확히 CONFIG_FILE인지 확인
        if event.src_path == CONFIG_FILE:
            logging.debug(f"Modification event detected for {CONFIG_FILE}. Debouncing...")

            # 기존 디바운스 작업이 실행 중이면 취소 (마지막 변경만 처리)
            if self._debounce_task and not self._debounce_task.done():
                self._debounce_task.cancel()
                logging.debug("Cancelled previous debounce task.")

            # 새 디바운스 작업 예약 (메인 이벤트 루프에서 안전하게 실행)
            async def schedule_sync():
                try:
                    # 지정된 시간만큼 대기
                    await asyncio.sleep(self._debounce_time)
                    # 대기 후 실제 동기화 작업 실행
                    await self._sync_task()
                except asyncio.CancelledError:
                    # 디바운스 작업이 취소된 경우 로깅
                    logging.debug("Debounce task cancelled.")
                except Exception as e:
                    # 예약된 작업 실행 중 에러 로깅
                    logging.error(f"Error in scheduled sync task: {e}", exc_info=True)

            # run_coroutine_threadsafe를 사용하여 watchdog 스레드에서 메인 루프로 코루틴 실행 요청
            self._debounce_task = asyncio.run_coroutine_threadsafe(schedule_sync(), self.loop)
            logging.debug(f"Scheduled new sync task after debounce period ({self._debounce_time}s).")

async def user_processing_wrapper(
    user_id_wrap: str,
    db_data_wrap: Dict[str, Any],
    guild_role_pairs: List[Tuple[discord.Guild, Optional[discord.Role]]],
    current_check_timestamp: int,
    process_semaphore: asyncio.Semaphore
):
    user_id_str = user_id_wrap
    original_status = db_data_wrap.get("status", 'X')
    refresh_token = db_data_wrap.get("refresh_token")

    user_final_status = original_status
    user_new_tokens: Optional[Tuple[str, str]] = None
    user_is_perm_fail = False
    token_action_code = '0'

    if original_status == 'O':
        if not refresh_token:
            logging.warning(f"[AutoCheck-Wrapper {user_id_str}] Missing refresh token. Marking permanent failure.")
            user_final_status = 'X'
            user_is_perm_fail = True
        else:
            logging.debug(f"[AutoCheck-Wrapper {user_id_str}] Attempting token refresh...")
            new_access, new_refresh = await refresh_access_token(refresh_token)
            if new_access and new_refresh:
                logging.info(f"[AutoCheck-Wrapper {user_id_str}] Token refresh successful.")
                user_final_status = 'O'
                user_new_tokens = (new_access, new_refresh)
                token_action_code = '1'
            else:
                logging.warning(f"[AutoCheck-Wrapper {user_id_str}] Token refresh failed. Marking permanent failure.")
                user_final_status = 'X'
                user_is_perm_fail = True

    guild_processing_tasks: List[asyncio.Task] = []
    current_token_for_guilds = user_new_tokens[0] if user_new_tokens else None

    if not guild_role_pairs:
        logging.info(f"[AutoCheck-Wrapper {user_id_str}] No guilds to process for this user.")
    else:
        for guild_obj, role_obj in guild_role_pairs:
            guild_processing_tasks.append(asyncio.create_task(process_single_user(
                guild_obj,
                user_id_str,
                role_obj,
                current_check_timestamp,
                process_semaphore,
                determined_user_status=user_final_status,
                current_access_token=current_token_for_guilds
            )))

    processed_guild_results_list: List[Dict[str, Any]] = []
    if guild_processing_tasks:
        guild_results = await asyncio.gather(*guild_processing_tasks, return_exceptions=True)
        for guild_result in guild_results:
            if isinstance(guild_result, Exception):
                processed_guild_results_list.append({"guild_id": "ERROR", "message_code": "99", "detail": str(guild_result)})
                logging.error(f"[AutoCheck-Wrapper {user_id_str}] Guild task failed: {guild_result}", exc_info=guild_result)
            elif isinstance(guild_result, dict):
                role_code = guild_result.get('role_action_code', '?')
                guild_result["message_code"] = f"{token_action_code}{role_code}"
                processed_guild_results_list.append(guild_result)

    final_result = {
        "user_id": user_id_str,
        "needs_db_update": True,
        "final_status": user_final_status,
        "new_tokens": user_new_tokens,
        "is_permanent_failure": user_is_perm_fail,
        "status_changed": (original_status == 'O' and user_final_status == 'X'),
        "guild_processing_results": processed_guild_results_list
    }
    return final_result

@tasks.loop(hours=1)
async def automated_token_check():
    if not hasattr(automated_token_check, '_lock') or automated_token_check._lock is None:
         automated_token_check._lock = asyncio.Lock()

    if automated_token_check._lock.locked():
        logging.warning("[AutoCheck-Staggered] Previous run is still ongoing. Skipping this cycle.")
        return

    async with automated_token_check._lock:
        logging.info("[AutoCheck-Staggered] Automated token check batch started.")
        start_time_task = asyncio.get_event_loop().time()
        current_check_timestamp = int(time.time())

        log_channel: Optional[discord.TextChannel] = None
        if ADMIN_LOG_CHANNEL_ID:
            log_channel = bot.get_channel(ADMIN_LOG_CHANNEL_ID)
            if not log_channel or not isinstance(log_channel, discord.TextChannel):
                logging.error(f"[AutoCheck-Staggered] ADMIN_LOG_CHANNEL ({ADMIN_LOG_CHANNEL_ID}) is invalid.")
                log_channel = None

        logging.info(f"[AutoCheck-Staggered] Fetching up to {USERS_TO_PROCESS_PER_RUN} users checked more than 12 hours ago.")
        try:
            users_to_process = await get_users_to_check_db(USERS_TO_PROCESS_PER_RUN)
        except Exception as e_fetch:
            logging.error(f"[AutoCheck-Staggered] Failed to fetch users from DB: {e_fetch}", exc_info=True)
            users_to_process = []

        if not users_to_process:
            logging.info("[AutoCheck-Staggered] No users found requiring a check in this batch.")
            return

        logging.info(f"[AutoCheck-Staggered] Processing batch of {len(users_to_process)} users.")

        try:
            all_config_data = await asyncio.to_thread(load_config)
            current_accessible_guild_objects: Dict[str, discord.Guild] = {str(g.id): g for g in bot.guilds}

            user_guild_role_map: Dict[str, List[Tuple[discord.Guild, Optional[discord.Role]]]] = {}
            target_user_ids = {u['user_id'] for u in users_to_process}

            for gid_str, gconf in all_config_data.items():
                if gid_str not in current_accessible_guild_objects:
                    continue

                guild_obj = current_accessible_guild_objects[gid_str]
                role_id = gconf.get("role_id")
                role_obj = guild_obj.get_role(role_id) if role_id else None

                config_users_in_guild = set(str(u) for u in gconf.get("users", []))
                batch_users_in_guild = target_user_ids.intersection(config_users_in_guild)

                for user_id in batch_users_in_guild:
                    user_guild_role_map.setdefault(user_id, []).append((guild_obj, role_obj))

        except Exception as e_prep:
             logging.error(f"[AutoCheck-Staggered] Failed to prepare guild/user data: {e_prep}", exc_info=True)
             return

        processing_tasks: List[asyncio.Task] = []
        process_semaphore = asyncio.Semaphore(10)

        for user_data in users_to_process:
            user_id = user_data['user_id']
            guild_role_pairs = user_guild_role_map.get(user_id, [])

            processing_tasks.append(asyncio.create_task(
                user_processing_wrapper(
                    user_id,
                    user_data,
                    guild_role_pairs,
                    current_check_timestamp,
                    process_semaphore
                )
            ))

        final_user_results: List[Dict[str, Any]] = []
        if processing_tasks:
            gathered_wrapper_results = await asyncio.gather(*processing_tasks, return_exceptions=True)
            for res in gathered_wrapper_results:
                if isinstance(res, Exception):
                    logging.error(f"[AutoCheck-Staggered] User wrapper task failed critically: {res}", exc_info=res)
                elif isinstance(res, dict):
                    final_user_results.append(res)
                else:
                    logging.warning(f"[AutoCheck-Staggered] Unexpected result type from user wrapper: {type(res)}")

        db_update_tasks: List[asyncio.Task] = []
        db_update_semaphore = asyncio.Semaphore(30)
        users_updated_db = 0; users_failed_db_update = 0

        async def update_db_task_wrapper(user_result_data: Dict[str, Any]):
            async with db_update_semaphore:
                uid = user_result_data["user_id"]
                if not user_result_data.get("needs_db_update"):
                    return None

                f_status = user_result_data["final_status"]
                n_tokens = user_result_data["new_tokens"]
                access, refresh = (n_tokens[0], n_tokens[1]) if n_tokens else (None, None)
                # Ensure permanent failures clear tokens regardless of refresh attempt success
                if user_result_data["is_permanent_failure"]:
                     access, refresh, f_status = None, None, 'X'

                success = await update_user_after_check(uid, f_status, access, refresh, current_check_timestamp)
                return success

        for user_res in final_user_results:
             db_update_tasks.append(asyncio.create_task(update_db_task_wrapper(user_res)))

        if db_update_tasks:
            db_task_results = await asyncio.gather(*db_update_tasks, return_exceptions=True)
            for db_res in db_task_results:
                 if isinstance(db_res, Exception):
                     users_failed_db_update += 1
                     logging.error(f"[AutoCheck-Staggered] DB update task failed with exception: {db_res}", exc_info=db_res)
                 elif db_res is True:
                     users_updated_db += 1
                 elif db_res is False:
                     users_failed_db_update += 1
                 elif db_res is None:
                     pass

        logging.info(f"[AutoCheck-Staggered] DB Update Phase: {users_updated_db} success, {users_failed_db_update} failed.")

        permanently_failed_users = {res["user_id"] for res in final_user_results if res.get("is_permanent_failure")}
        if permanently_failed_users:
            logging.warning(f"[AutoCheck-Staggered] {len(permanently_failed_users)} users marked permanent failure. Removing from config.")
            try:
                async with CONFIG_LOCK:
                    current_config = await asyncio.to_thread(load_config)
                    removed_count = 0; changed_in_lock = False
                    for gid in list(current_config.keys()):
                        if "users" in current_config.get(gid, {}):
                            guild_users_set = set(str(u) for u in current_config[gid].get("users", []))
                            initial_count = len(guild_users_set)
                            users_to_keep = guild_users_set - permanently_failed_users
                            if len(users_to_keep) < initial_count:
                                current_config[gid]["users"] = sorted(list(users_to_keep))
                                removed_count += (initial_count - len(users_to_keep))
                                changed_in_lock = True
                    if changed_in_lock:
                        save_success = await asyncio.to_thread(save_config, current_config)
                        if save_success:
                            logging.info(f"[AutoCheck-Staggered] Config saved. Removed {removed_count} entries for {len(permanently_failed_users)} users.")
                            await asyncio.to_thread(sync_guild_configs)
                        else: logging.error("[AutoCheck-Staggered] Config save failed after removing users!")
                    else: logging.info("[AutoCheck-Staggered] No users needed removal from config.")
            except Exception as e_cfg_rem:
                 logging.error(f"[AutoCheck-Staggered] Error removing users from config: {e_cfg_rem}", exc_info=True)

        invalidated_users_dm_info: Dict[str, Set[str]] = {}
        for user_res in final_user_results:
             if user_res.get("status_changed"):
                 uid = user_res["user_id"]
                 affected_guilds = {g_res["guild_id"] for g_res in user_res.get("guild_processing_results", []) if isinstance(g_res, dict) and g_res.get("guild_id") != "ERROR"}
                 if affected_guilds: invalidated_users_dm_info[uid] = affected_guilds

        dm_sent, dm_failed, dm_forbid, dm_edit_failed = 0, 0, 0, 0
        if invalidated_users_dm_info:
            logging.info(f"[AutoCheck-Staggered] Sending {len(invalidated_users_dm_info)} status change DMs...")
            try: redirect_uri_encoded = quote(REDIRECT_URI, safe='')
            except Exception: redirect_uri_encoded = "https%3A%2F%2Fdicotm20.com%2Fverify"

            dm_tasks = []
            async def send_dm_wrapper(user_id_dm: str, affected_gids: Set[str]):
                nonlocal dm_sent, dm_failed, dm_forbid, dm_edit_failed
                try:
                    user = await bot.fetch_user(int(user_id_dm))
                    if not user: return "fetch_fail"

                    affected_names = set()
                    for g_id in affected_gids:
                        guild = current_accessible_guild_objects.get(g_id)
                        affected_names.add(guild.name if guild else f"ID: {g_id}")

                    g_list = "\n".join(f"- {n}" for n in sorted(list(affected_names)))
                    emb = discord.Embed(
                        title="⚠️ 서버 인증 상태 변경 알림",
                        description="회원님의 디스코드 계정 인증 토큰 갱신에 문제가 발생하여 다음 서버에서의 인증 상태가 해제/제거되었을 수 있습니다.\n아래 버튼을 눌러 **한 번에 재인증**하거나, 각 서버에서 개별적으로 인증해주세요.",
                        color=discord.Color.orange(), timestamp=datetime.now() )
                    emb.add_field(name="영향 서버", value=g_list if g_list else "정보 없음", inline=False)
                    emb.set_footer(text="문제가 지속되면 관리자에게 문의하세요.")
                    view = discord.ui.View(); btn = discord.ui.Button(label=f"🔄 모든 서버({len(affected_gids)}) 재인증", style=discord.ButtonStyle.link, url="https://discord.com", disabled=True); view.add_item(btn); sent_dm = None

                    try: sent_dm = await user.send(embed=emb, view=view)
                    except discord.Forbidden: return "forbidden"
                    except Exception as send_e: logging.error(f"[AutoCheck-DM] Failed send to {user_id_dm}: {send_e}"); return "send_fail"
                    if not sent_dm: return "send_fail"

                    url = None
                    if affected_gids and serializer:
                        try:
                            state_data = {
                                'type':'multi_reverify',
                                'user_id':user_id_dm,
                                'guild_ids':sorted(list(affected_gids)),
                                'nonce':os.urandom(16).hex(),
                                'original_dm_id':sent_dm.id # Store the sent DM ID here
                            }
                            state = serializer.dumps(state_data)
                            url=f"https://discord.com/oauth2/authorize?client_id={CLIENT_ID}&response_type=code&redirect_uri={redirect_uri_encoded}&scope=identify+email+guilds.join&state={state}"
                        except Exception as state_e: logging.error(f"[AutoCheck-DM] State creation fail {user_id_dm}: {state_e}")

                    if url:
                        btn.url = url; btn.disabled = False
                        try: await sent_dm.edit(view=view); return "success"
                        except Exception as edit_e: logging.error(f"[AutoCheck-DM] Failed edit {user_id_dm}: {edit_e}"); return "edit_fail"
                    else:
                        logging.warning(f"[AutoCheck-DM] URL generation failed for {user_id_dm}, DM edit skipped.")
                        return "url_fail"
                except discord.NotFound: return "fetch_fail"
                except Exception as e_dm: logging.error(f"[AutoCheck-DM] Error in DM wrapper {user_id_dm}: {e_dm}"); return "send_fail"

            for uid, gids_set in invalidated_users_dm_info.items():
                 dm_tasks.append(asyncio.create_task(send_dm_wrapper(uid, gids_set)))
                 await asyncio.sleep(0.7)

            if dm_tasks:
                 dm_results = await asyncio.gather(*dm_tasks)
                 for res in dm_results:
                     if res == "success": dm_sent += 1
                     elif res == "forbidden": dm_forbid += 1
                     elif res == "edit_fail": dm_edit_failed += 1; dm_failed += 1
                     else: dm_failed += 1

            logging.info(f"[AutoCheck-DM] DM Phase Complete. Sent: {dm_sent}, Forbidden: {dm_forbid}, Failed(Send/Edit/Other): {dm_failed}/{dm_edit_failed}")

        if log_channel:
            logging.info("[AutoCheck-Staggered] Formatting results for log channel...")
            try:
                embed = discord.Embed(title=f"📊 자동 검증 배치 결과 ({datetime.now():%Y-%m-%d %H:%M:%S})", description=f"처리 대상: {len(users_to_process)}명", color=discord.Color.blue(), timestamp=datetime.now())
                code_explanation = ("**결과:** `User: Guild: AB` (A:토큰, B:역할) | `A`: 1=갱신, 0=실패/안함 | `B`: 1=추가, 0=유지/제거, 2=실패, 9=오류")
                embed.add_field(name="코드 설명", value=code_explanation, inline=False)

                guild_summary: Dict[str, List[str]] = {}
                total_processed_pairs = 0
                for user_res in final_user_results:
                    for guild_res in user_res.get("guild_processing_results", []):
                         if isinstance(guild_res, dict):
                              g_name = guild_res.get("guild_name", "?"); g_id = guild_res.get("guild_id", "?"); u_id = user_res.get("user_id"); m_code = guild_res.get("message_code", "??"); detail = guild_res.get("detail", "")
                              key = f"{g_name} ({g_id})"
                              msg = f"`{u_id}`: `{m_code}`{f' ({detail})' if detail else ''}"
                              guild_summary.setdefault(key, []).append(msg)
                              total_processed_pairs += 1

                embeds_to_send = [embed]

                if not guild_summary: embed.add_field(name="처리 결과", value="처리 결과 없음.", inline=False)
                else:
                    field_count = 0; char_count = len(embed.title or "") + len(embed.description or "") + len(code_explanation or "") + 100 # Estimate footer length etc.
                    embeds_to_send = [embed]
                    for guild_key in sorted(guild_summary.keys()):
                        results = sorted(guild_summary[guild_key]); field_name = f"📄 {guild_key}"
                        full_value = "```\n" + "\n".join(results) + "\n```"; field_value = full_value[:1010] + "\n... (생략)```" if len(full_value) > 1024 else full_value; field_len = len(field_name) + len(field_value)
                        current_embed = embeds_to_send[-1]
                        if field_count >= 24 or char_count + field_len > 5800:
                            current_embed = discord.Embed(title=f"{embed.title} (계속)", color=embed.color); embeds_to_send.append(current_embed); field_count = 0; char_count = len(current_embed.title or "")
                        current_embed.add_field(name=field_name, value=field_value, inline=False); field_count += 1; char_count += field_len

                end_time_task = asyncio.get_event_loop().time(); elapsed = round(end_time_task - start_time_task, 2)
                footer = (f"총 {total_processed_pairs} 쌍 처리 | DB갱신 {users_updated_db}/{len(db_update_tasks)} | 영구실패 {len(permanently_failed_users)} | DM(O->X) {dm_sent}/{dm_sent+dm_forbid+dm_failed} | {elapsed}초")
                if embeds_to_send: embeds_to_send[-1].set_footer(text=footer)
                for emb in embeds_to_send: await log_channel.send(embed=emb); await asyncio.sleep(0.5)
            except Exception as e_log: logging.error(f"[AutoCheck-Staggered] Log send error: {e_log}", exc_info=True)

        logging.info(f"[AutoCheck-Staggered] Batch finished in {round(asyncio.get_event_loop().time() - start_time_task, 2)}s.")

# Initialize the lock attribute for the task loop outside the function definition
automated_token_check._lock = None

@automated_token_check.before_loop
async def before_automated_token_check():
    logging.info("[AutoCheck-Staggered] Waiting for bot to be ready...")
    await bot.wait_until_ready()
    logging.info("[AutoCheck-Staggered] Bot ready. Task will start.")

@bot.tree.command(name="check_my_server", description="본인이 관리자로 등록된 서버 목록과 사용자 수를 확인합니다.")
async def check_my_server(interaction: discord.Interaction):
    user_id_str = str(interaction.user.id)
    log_prefix = f"[CheckMyServer User {user_id_str}]"
    logging.info(f"{log_prefix} Command invoked.")

    await interaction.response.defer(ephemeral=True, thinking=True)
    followup = interaction.followup

    managed_servers = []
    try:
        # 설정 파일 로드 (파일 I/O는 스레드에서)
        config_data = await asyncio.to_thread(load_config, CONFIG_FILE)

        if not isinstance(config_data, dict):
             logging.error(f"{log_prefix} Config data is not a dictionary.")
             await followup.send("⚙️ 설정 정보를 읽어오는 데 문제가 발생했습니다.", ephemeral=True)
             return

        # 설정 데이터를 순회하며 admin_user_id 비교
        for guild_id, conf in config_data.items():
            if isinstance(conf, dict):
                # admin_user_id가 존재하고, 명령어를 실행한 사용자의 ID와 일치하는지 확인
                if str(conf.get("admin_user_id")) == user_id_str:
                    user_count = len(conf.get("users", []))
                    # 봇이 현재 접근 가능한 길드인지 확인하여 이름 가져오기 시도
                    guild = bot.get_guild(int(guild_id))
                    guild_name = guild.name if guild else "알 수 없는 서버" # 봇이 길드에 없으면 이름 대신 ID 표시
                    managed_servers.append({
                        "id": guild_id,
                        "name": guild_name,
                        "user_count": user_count
                    })

        # 결과 Embed 생성
        if not managed_servers:
            await followup.send("ℹ️ 본인이 관리자로 등록된 서버를 찾을 수 없습니다.", ephemeral=True)
            return

        embed = discord.Embed(
            title=f"🔑 {interaction.user.display_name}님의 관리 서버 목록",
            description=f"총 {len(managed_servers)}개의 서버가 관리자로 등록되어 있습니다.",
            color=discord.Color.blue(),
            timestamp=datetime.now()
        )

        # 서버 목록 필드 추가 (최대 25개 필드 제한 고려)
        for i, server_info in enumerate(managed_servers):
            if i >= 25:
                embed.add_field(name="...", value=f"외 {len(managed_servers) - 25}개 서버 생략", inline=False)
                break
            embed.add_field(
                name=f"{i+1}. {server_info['name']} (`{server_info['id']}`)",
                value=f"인증된 사용자: {server_info['user_count']}명",
                inline=False
            )

        embed.set_footer(text="sync_config.json 기준")
        await followup.send(embed=embed, ephemeral=True)
        logging.info(f"{log_prefix} Displayed {len(managed_servers)} managed servers.")

    except Exception as e:
        logging.error(f"{log_prefix} An unexpected error occurred: {e}", exc_info=True)
        try:
            # is_done()으로 확인 후 응답 시도
            if not interaction.response.is_done():
                 await interaction.response.send_message("⚙️ 서버 정보 확인 중 오류가 발생했습니다.", ephemeral=True)
            else:
                 await followup.send("⚙️ 서버 정보 확인 중 오류가 발생했습니다.", ephemeral=True)
        except Exception:
             pass # 오류 메시지 전송 실패 시 무시
        
@bot.tree.command(name="start_setup", description="봇 설정을 시작합니다. 인증/로그 채널이 자동 생성됩니다 (관리자 전용).") # 설명 수정
@app_commands.describe(
    serial_code="등록된 유효한 시리얼 코드를 입력하세요.",
    role="인증 시 부여할 역할을 선택하세요."
)
@app_commands.checks.has_permissions(administrator=True)
async def start_setup(
    interaction: discord.Interaction,
    serial_code: str,
    role: discord.Role
):
    guild = interaction.guild
    if not guild:
        await interaction.response.send_message("❌ 이 명령어는 서버 내에서만 사용할 수 있습니다.", ephemeral=True)
        return

    guild_id_str = str(guild.id)
    log_prefix = f"[StartSetup Guild {guild_id_str} User {interaction.user.id}]"
    logging.info(f"{log_prefix} Setup command initiated...") # 로그 수정

    await interaction.response.defer(ephemeral=True, thinking=True)
    followup = interaction.followup

    try:
        async with CONFIG_LOCK:
            config_data_check = await asyncio.to_thread(load_config)
            if guild_id_str in config_data_check:
                await followup.send("❌ 이 서버는 이미 설정되어 있습니다. 설정을 초기화하려면 먼저 등록 해제 후 다시 시도해주세요.", ephemeral=True)
                return

        serials_map = {}
        serial_info: Optional[Dict[str, Any]] = None # 시리얼 정보 저장용
        serial_expires_at_str = None
        assigned_rank = 1 # 기본값
        assigned_credit = 500 # 기본값
        is_serial_valid = False
        save_success_serials = False
        valid_date_format = "%Y-%m-%d"

        async with SERIAL_LOCK:
            log_prefix_lock = f"{log_prefix} [SerialLock]"
            # load_serials는 이제 Dict[str, Dict[str, Any]] 반환
            serials_map = await asyncio.to_thread(load_serials, SERIAL_FILE)

            serial_info = serials_map.get(serial_code) # 키로 정보 조회

            if not serial_info:
                is_serial_valid = False
            else:
                serial_expires_at_str = serial_info.get("expires_at")
                rank_from_serial = serial_info.get("rank")

                # 만료일 및 rank 유효성 재확인
                if serial_expires_at_str is None or rank_from_serial is None or rank_from_serial not in [1, 2]:
                     logging.error(f"{log_prefix_lock} Invalid data found for serial '{serial_code}'.")
                     is_serial_valid = False
                else:
                    try:
                        expires_date = datetime.strptime(serial_expires_at_str, valid_date_format).date()
                        today = date.today()
                        if expires_date < today:
                            logging.warning(f"{log_prefix_lock} Serial code '{serial_code}' has expired (Expired date: {serial_expires_at_str}).")
                            is_serial_valid = False
                        else:
                            is_serial_valid = True
                            assigned_rank = rank_from_serial # 유효하면 rank 할당
                            assigned_credit = 1000 if assigned_rank == 2 else 500 # credit 계산
                            del serials_map[serial_code] # 사용된 코드 제거 준비
                            save_success_serials = await asyncio.to_thread(save_serials, serials_map, SERIAL_FILE)
                            if not save_success_serials:
                                logging.error(f"{log_prefix_lock} Failed to save serials after removing used code {serial_code}.")
                    except ValueError:
                        logging.error(f"{log_prefix_lock} Invalid date format for serial '{serial_code}': {serial_expires_at_str}. Treating as invalid.")
                        is_serial_valid = False

        if not is_serial_valid:
            message = f"❌ 잘못되었거나 만료된 시리얼 코드입니다: `{serial_code}`."
            if serial_expires_at_str: message += f" (만료 정보: {serial_expires_at_str})"
            await followup.send(message, ephemeral=True)
            return

        if not save_success_serials: # is_serial_valid는 True인 상태
             await followup.send("⚠️ 시리얼 코드는 유효하지만, 사용된 코드 제거에 실패했습니다. 설정은 계속 진행합니다.", ephemeral=True)

        # --- (권한 검사 로직은 동일) ---
        bot_member = guild.me
        if not bot_member.guild_permissions.manage_roles:
            await followup.send("❌ 봇에게 **'역할 관리' 권한**이 없습니다.", ephemeral=True)
            return
        if bot_member.top_role <= role:
            await followup.send(f"❌ 봇 역할({bot_member.top_role.mention})이 대상 역할({role.mention})보다 낮아 관리할 수 없습니다. 봇 역할을 더 위로 옮겨주세요.", ephemeral=True)
            return
        if role.is_default() or role.is_integration() or role.is_bot_managed():
            await followup.send("❌ `@everyone`, 통합 또는 봇 관리 역할은 인증 역할로 지정할 수 없습니다.", ephemeral=True)
            return
        logging.info(f"{log_prefix} Role permission checks passed.")

        if not bot_member.guild_permissions.manage_channels:
            await followup.send("❌ 봇에게 **'채널 관리' 권한**이 없어 인증/로그 채널을 자동으로 생성할 수 없습니다. 권한을 부여해주세요.", ephemeral=True)
            return
        logging.info(f"{log_prefix} Channel management permission check passed.")

        # --- (채널 생성 로직은 동일, 관리자 채널 제외) ---
        category_name = "DICOTM20 인증"
        verify_channel_name = "✅ㅣ인증"
        log_channel_name = "📊ㅣ인증-로그"
        category: Optional[discord.CategoryChannel] = None
        new_verify_channel: Optional[discord.TextChannel] = None
        new_log_channel: Optional[discord.TextChannel] = None

        try:
            category = discord.utils.get(guild.categories, name=category_name)
            category_overwrites = {
                guild.default_role: discord.PermissionOverwrite(view_channel=False),
                guild.me: discord.PermissionOverwrite(manage_channels=True, manage_permissions=True, view_channel=True)
            }
            if not category:
                logging.info(f"{log_prefix} Creating category '{category_name}'...")
                category = await guild.create_category(name=category_name, overwrites=category_overwrites)
                logging.info(f"{log_prefix} Category '{category.name}' created (ID: {category.id}).")
            else:
                 logging.info(f"{log_prefix} Found existing category '{category.name}' (ID: {category.id}). Will create channels within.")

            verify_overwrites = {
                guild.default_role: discord.PermissionOverwrite(view_channel=True, send_messages=False),
                guild.me: discord.PermissionOverwrite(send_messages=True, embed_links=True, manage_messages=True, view_channel=True)
            }
            log_overwrites = {
                guild.default_role: discord.PermissionOverwrite(view_channel=False),
                guild.me: discord.PermissionOverwrite(view_channel=True, send_messages=True, embed_links=True)
            }

            logging.info(f"{log_prefix} Creating NEW verification channel '{verify_channel_name}'...")
            new_verify_channel = await category.create_text_channel(name=verify_channel_name, overwrites=verify_overwrites)
            logging.info(f"{log_prefix} NEW verification channel created (ID: {new_verify_channel.id}).")

            logging.info(f"{log_prefix} Creating NEW log channel '{log_channel_name}'...")
            new_log_channel = await category.create_text_channel(name=log_channel_name, overwrites=log_overwrites)
            logging.info(f"{log_prefix} NEW log channel created (ID: {new_log_channel.id}).")

        except discord.Forbidden:
            logging.error(f"{log_prefix} Forbidden error during channel/category creation.")
            await followup.send("❌ 카테고리 또는 채널 생성 중 권한 오류가 발생했습니다. 봇에게 '채널 관리' 권한과 적절한 역할 순서가 있는지 확인해주세요.", ephemeral=True)
            return
        except Exception as e_create:
            logging.error(f"{log_prefix} Error creating channels/category: {e_create}", exc_info=True)
            await followup.send(f"⚙️ 채널 생성 중 오류가 발생했습니다: {type(e_create).__name__}", ephemeral=True)
            return

        if not new_verify_channel or not new_log_channel:
            logging.error(f"{log_prefix} Channel creation failed unexpectedly (verify or log).")
            await followup.send("⚙️ 채널 생성에 실패했습니다. 잠시 후 다시 시도해주세요.", ephemeral=True)
            return

        verify_channel_id = new_verify_channel.id
        log_channel_id = new_log_channel.id

        save_success_config = False
        try:
            async with CONFIG_LOCK:
                log_prefix_cfg_lock = f"{log_prefix} [ConfigLock]"
                config_data = await asyncio.to_thread(load_config)
                # --- ★★★ rank, credit 저장 추가 ★★★ ---
                config_data[guild_id_str] = {
                    "role_id": role.id,
                    "verify_channel_id": verify_channel_id,
                    "log_channel_id": log_channel_id,
                    "admin_user_id": str(interaction.user.id),
                    "users": [],
                    "expires_at": serial_expires_at_str,
                    "rank": assigned_rank,     # 할당된 rank 저장
                    "credit": assigned_credit # 계산된 credit 저장
                }
                # --- ★★★ 추가 끝 ★★★ ---
                save_success_config = await asyncio.to_thread(save_config, config_data, CONFIG_FILE)
                if not save_success_config: logging.error(f"{log_prefix_cfg_lock} Failed to save config file.")
                else: logging.info(f"{log_prefix_cfg_lock} Config file saved successfully for new guild with Rank {assigned_rank} / Credit {assigned_credit}.")

            if not save_success_config:
                 await followup.send("❌ 설정을 파일에 저장하는 중 오류가 발생했습니다.", ephemeral=True)
                 return

            await asyncio.to_thread(sync_guild_configs)
            logging.info(f"{log_prefix} In-memory config synced.")

        except asyncio.TimeoutError:
             logging.error(f"{log_prefix} Timeout acquiring config lock.")
             await followup.send("⚙️ 설정 저장 중 잠시 문제가 발생했습니다. (Timeout)", ephemeral=True)
             return
        except Exception as cfg_e:
             logging.error(f"{log_prefix} Error during config file handling: {cfg_e}", exc_info=True)
             await followup.send("⚙️ 설정 파일 처리 중 오류가 발생했습니다.", ephemeral=True)
             return

        await send_verification_message(guild_id_str)

        embed = discord.Embed(title="✅ 서버 설정 완료", description="성공적으로 봇 설정을 완료했습니다.", color=discord.Color.green(), timestamp=datetime.now())
        embed.add_field(name="🔧 인증 역할", value=role.mention, inline=False)
        embed.add_field(name="📢 인증 채널", value=new_verify_channel.mention, inline=False)
        embed.add_field(name="📊 인증 로그 채널", value=new_log_channel.mention, inline=False)
        embed.add_field(name="⭐ 등급 (Rank)", value=f"`{assigned_rank}`", inline=True)
        embed.add_field(name="💰 크레딧 (Credit)", value=f"`{assigned_credit}`", inline=True)
        # --- 만료 시점 표시 수정 ---
        try:
            expires_date = datetime.strptime(serial_expires_at_str, "%Y-%m-%d").date()
            effective_expiry_dt = expires_date + timedelta(days=1)
            display_expiry = effective_expiry_dt.strftime("%Y-%m-%d 00:00")
        except (ValueError, TypeError): # serial_expires_at_str이 None이거나 잘못된 형식일 경우 대비
            display_expiry = f"{serial_expires_at_str or '알 수 없음'} (형식 오류?)"

        embed.add_field(name="⏳ 서버 만료 시점", value=f"`{display_expiry}`", inline=False) # 필드 이름 변경
        # --- 수정 끝 ---
        if not save_success_serials:
             embed.add_field(name="⚠️ 시리얼 경고", value="사용된 시리얼 코드를 목록에서 제거하는 데 실패했습니다.", inline=False)
        embed.set_footer(text="설정이 성공적으로 적용되었습니다.")
        # --- ★★★ 수정 끝 ★★★ ---
        await followup.send(embed=embed, ephemeral=True)
        logging.info(f"{log_prefix} Setup completed successfully with Rank {assigned_rank} / Credit {assigned_credit} / Expiry {serial_expires_at_str}.")

    except asyncio.TimeoutError:
        logging.error(f"{log_prefix} Timeout acquiring serial lock.")
        await followup.send("⚙️ 시리얼 처리 중 잠시 문제가 발생했습니다. (Timeout)", ephemeral=True)
    except Exception as e:
        logging.error(f"{log_prefix} An unexpected error occurred during setup: {e}", exc_info=True)
        try:
            if interaction.response.is_done():
                await followup.send(f"⚙️ 설정 중 예상치 못한 오류 발생: {type(e).__name__}", ephemeral=True)
            else:
                await interaction.response.send_message(f"⚙️ 설정 중 예상치 못한 오류 발생: {type(e).__name__}", ephemeral=True)
        except Exception as e_followup:
             logging.error(f"{log_prefix} Failed to send final error message: {e_followup}")

@start_setup.error
async def start_setup_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    if isinstance(error, app_commands.MissingPermissions):
        await interaction.response.send_message("❌ 이 명령어를 사용하려면 서버 관리자 권한이 필요합니다.", ephemeral=True)
    else:
        logging.error(f"Unhandled error in start_setup command: {error}", exc_info=error)
        try:
             if not interaction.response.is_done():
                 await interaction.response.send_message("⚙️ 명령어 처리 중 오류가 발생했습니다.", ephemeral=True)
             else:
                  await interaction.followup.send("⚙️ 명령어 처리 중 오류가 발생했습니다.", ephemeral=True)
        except Exception as e_resp:
            logging.error(f"Failed to send error message for start_setup: {e_resp}")

@bot.tree.command(name="config_role_id", description="이 서버의 인증 역할을 변경합니다 (관리자 전용).")
@app_commands.describe(new_role="새로운 인증 역할을 선택하세요.")
@app_commands.checks.has_permissions(administrator=True)
async def config_role_id(interaction: discord.Interaction, new_role: discord.Role):
    """슬래시 커맨드: 서버의 인증 역할 ID를 업데이트합니다."""
    guild = interaction.guild
    if not guild:
        await interaction.response.send_message("❌ 이 명령어는 서버 내에서만 사용할 수 있습니다.", ephemeral=True)
        return

    log_prefix = f"[ConfigRoleID Guild {guild.id} User {interaction.user.id}]"
    guild_id_str = str(guild.id)

    await interaction.response.defer(ephemeral=True, thinking=True)
    followup = interaction.followup

    try:
        # 1. 설정 파일 로드 및 서버 존재 확인
        logging.debug(f"{log_prefix} Loading config file...")
        config_data = await asyncio.to_thread(load_config, CONFIG_FILE)

        if guild_id_str not in config_data:
            logging.warning(f"{log_prefix} Guild not found in config. Run /start_setup first.")
            await followup.send("❌ 이 서버는 아직 설정되지 않았습니다. 먼저 `/start_setup` 명령어를 실행해주세요.", ephemeral=True)
            return
        
        # 선택적: 기존 설정에 필요한 키가 있는지 확인 (없으면 오류 가능성 있음)
        if "role_id" not in config_data.get(guild_id_str, {}):
            logging.warning(f"{log_prefix} 'role_id' key missing in existing config for this guild.")
            # 오류를 내거나, 키를 생성하도록 처리할 수 있음. 여기서는 일단 진행.
            
        current_role_id = config_data.get(guild_id_str, {}).get("role_id")

        # 2. 변경 사항 적용
        if current_role_id == new_role.id:
            await followup.send(f"ℹ️ 이미 인증 역할이 {new_role.mention}(으)로 설정되어 있습니다.", ephemeral=True)
            return
            
        config_data[guild_id_str]["role_id"] = new_role.id
        logging.info(f"{log_prefix} Updating role ID to {new_role.id}")

        # 3. 설정 파일 저장
        logging.debug(f"{log_prefix} Saving updated config file...")
        save_success = await asyncio.to_thread(save_config, config_data, CONFIG_FILE)
        if not save_success:
            logging.error(f"{log_prefix} Failed to save config file.")
            await followup.send("❌ 설정을 파일에 저장하는 중 오류가 발생했습니다.", ephemeral=True)
            return

        # 4. 메모리 내 설정 동기화
        logging.debug(f"{log_prefix} Re-syncing in-memory guild configs...")
        await asyncio.to_thread(sync_guild_configs)

        # 5. 성공 메시지 전송
        await followup.send(f"✅ 인증 역할이 {new_role.mention}(으)로 성공적으로 변경되었습니다.", ephemeral=True)
        logging.info(f"{log_prefix} Role ID updated successfully.")

    except Exception as e:
        logging.error(f"{log_prefix} An unexpected error occurred: {e}", exc_info=True)
        try:
            await followup.send(f"⚙️ 역할 변경 중 예상치 못한 오류가 발생했습니다.\n오류: {type(e).__name__}", ephemeral=True)
        except Exception as e_followup:
             logging.error(f"{log_prefix} Failed to send error followup message: {e_followup}")

@config_role_id.error
async def config_role_id_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    if isinstance(error, app_commands.MissingPermissions):
        await interaction.response.send_message("❌ 이 명령어를 사용하려면 서버 관리자 권한이 필요합니다.", ephemeral=True)
    else:
        logging.error(f"Unhandled error in config_role_id command: {error}", exc_info=error)
        try:
             if not interaction.response.is_done():
                 await interaction.response.send_message("⚙️ 명령어 처리 중 오류가 발생했습니다.", ephemeral=True)
             else:
                  await interaction.followup.send("⚙️ 명령어 처리 중 오류가 발생했습니다.", ephemeral=True)
        except Exception as e_resp:
            logging.error(f"Failed to send error message for config_role_id: {e_resp}")

class DiscordLogHandler(logging.Handler):
    """
    로그 레코드를 받아 지정된 Discord 채널에 Embed로 전송하는 핸들러.
    asyncio.Queue를 사용하여 비동기 전송 처리.
    """
    def __init__(self, bot_instance: commands.Bot, channel_id: int, loop: asyncio.AbstractEventLoop):
        super().__init__()
        self.bot = bot_instance
        self.channel_id = channel_id
        self.loop = loop
        self.queue = asyncio.Queue()
        self.consumer_task = self.loop.create_task(self._log_consumer())
        self.channel: Optional[discord.TextChannel] = None # 채널 객체 캐싱용

        # 로그 레벨별 색상 지정
        self.level_colors = {
            logging.CRITICAL: discord.Color.dark_red(),
            logging.ERROR: discord.Color.red(),
            logging.WARNING: discord.Color.orange(),
            logging.INFO: discord.Color.blue(),
            logging.DEBUG: discord.Color.greyple(),
        }

    def get_color(self, levelno: int) -> discord.Color:
        """로그 레벨에 맞는 Embed 색상을 반환합니다."""
        return self.level_colors.get(levelno, discord.Color.default())

    def format_record_for_embed(self, record: logging.LogRecord) -> Dict[str, Any]:
            """로그 레코드를 Embed 필드에 적합한 형식으로 만듭니다."""
            try:
                message = self.format(record) # 기본 포매터 사용
                if len(message) > 1000:
                    message = message[:1000] + "..."

                embed_data = {
                    "title": f"[{record.levelname}] - {record.name}",
                    "description": f"```\n{message}\n```",
                    "color": self.get_color(record.levelno).value,
                    # ---> 여기 수정: utcfromtimestamp 사용 <---
                    "timestamp": datetime.utcfromtimestamp(record.created).isoformat()
                }
                if record.levelno >= logging.ERROR and record.pathname and record.lineno:
                    embed_data["title"] += f" ({os.path.basename(record.pathname)}:{record.lineno})"

                return embed_data

            except Exception as e:
                # 포매팅 중 오류 발생 시 대체 데이터 반환
                return {
                    "title": f"[{record.levelname}] - Formatting Error",
                    "description": f"```\nError formatting log record: {e}\nOriginal Msg: {record.getMessage()}\n```",
                    "color": discord.Color.dark_grey(),
                    # ---> 여기도 동일하게 수정 <---
                    "timestamp": datetime.utcfromtimestamp(record.created).isoformat()
                }

    def emit(self, record: logging.LogRecord):
        """로그 레코드를 받아 큐에 Embed 데이터를 넣습니다."""
        if not self.bot.is_ready() or self.consumer_task.done():
             # 봇이 준비되지 않았거나 consumer 태스크가 종료되었으면 무시
             # (무한 루프 방지 및 시작/종료 단계 로그 과다 방지)
             # 필요시 파일 로그 등으로 기록 가능
             # print(f"Skipping Discord log: Bot not ready or consumer stopped. Level: {record.levelname}")
             return

        try:
            embed_data = self.format_record_for_embed(record)
            # 큐에 직접 Embed 객체 대신 딕셔너리 넣기 (나중에 consumer에서 생성)
            self.queue.put_nowait(embed_data)
        except asyncio.QueueFull:
            # 큐가 가득 찬 매우 드문 경우 (로그 폭주 시)
            print(f"Discord log queue is full! Log dropped: {record.getMessage()}") # 콘솔에 경고 출력
        except Exception as e:
            # emit 단계에서 예상치 못한 오류 발생 시
            print(f"Error in DiscordLogHandler.emit: {e}") # 콘솔에 오류 출력
            # 여기서 logging 사용 시 무한 루프 가능성 있으므로 print 사용

    async def _log_consumer(self):
        """큐에서 Embed 데이터를 꺼내 Discord 채널로 비동기 전송합니다."""
        await self.bot.wait_until_ready() # 봇 준비 완료까지 대기
        self.channel = self.bot.get_channel(self.channel_id)
        if not self.channel:
             print(f"ERROR: Discord log channel {self.channel_id} not found!")
             logging.error(f"[DiscordLogHandler] Log channel {self.channel_id} not found!")
             # Consumer 태스크 종료 또는 재시도 로직 추가 가능
             return # 채널 없으면 consumer 종료

        print(f"Discord log consumer started. Target channel: #{self.channel.name} ({self.channel_id})")
        logging.info(f"[DiscordLogHandler] Log consumer started for channel #{self.channel.name}")

        while True:
            try:
                embed_data = await self.queue.get()
                if embed_data is None: # 종료 신호 (선택적 구현)
                    break

                # 채널 객체가 유효한지 다시 확인 (봇이 서버에서 나가거나 채널 삭제 시)
                if not self.channel or self.channel.guild is None or self.channel.guild != self.bot.get_guild(self.channel.guild.id):
                     self.channel = self.bot.get_channel(self.channel_id) # 채널 재탐색
                     if not self.channel:
                          logging.warning(f"[DiscordLogHandler] Log channel {self.channel_id} became unavailable. Stopping consumer.")
                          print(f"Warning: Discord log channel {self.channel_id} unavailable.")
                          # 여기서 break 하거나 계속 시도할 수 있음
                          break # 일단 종료

                try:
                    # Embed 객체 생성 및 전송
                    embed = discord.Embed.from_dict(embed_data)
                    await self.channel.send(embed=embed)
                    await asyncio.sleep(0.5) # 기본적인 Rate Limit 방지용 딜레이
                except discord.Forbidden:
                    logging.warning(f"[DiscordLogHandler] Forbidden to send log message to channel {self.channel_id}.")
                    # 권한 문제 발생 시 잠시 대기 후 재시도하거나 consumer 종료 가능
                    await asyncio.sleep(60) # 1분 대기
                except discord.HTTPException as e:
                    logging.warning(f"[DiscordLogHandler] HTTP error sending log: {e.status} - {e.text}")
                    await asyncio.sleep(5) # 잠시 대기 후 재시도
                except Exception as e_send:
                    logging.error(f"[DiscordLogHandler] Error sending log via consumer: {e_send}", exc_info=True)
                    await asyncio.sleep(1) # 예상 못한 오류 시 짧게 대기

                self.queue.task_done() # 큐 작업 완료 표시

            except asyncio.CancelledError:
                 logging.info("[DiscordLogHandler] Log consumer task cancelled.")
                 break # 취소 시 루프 종료
            except Exception as e_consumer:
                 # Consumer 루프 자체의 예외 처리
                 logging.critical(f"[DiscordLogHandler] Critical error in log consumer loop: {e_consumer}", exc_info=True)
                 print(f"CRITICAL ERROR in Discord log consumer: {e_consumer}")
                 await asyncio.sleep(5) # 심각한 오류 발생 시 잠시 후 재시도

    async def close_async(self):
        """핸들러 비동기 종료 처리 (큐 처리 및 태스크 취소)."""
        logging.info("[DiscordLogHandler] Closing handler...")
        # 큐에 종료 신호 추가 (선택적) 또는 바로 취소
        # await self.queue.put(None)
        # await self.queue.join() # 큐의 모든 항목 처리 대기

        if self.consumer_task and not self.consumer_task.done():
             self.consumer_task.cancel()
             try:
                 await self.consumer_task # 태스크 종료 대기
             except asyncio.CancelledError:
                 logging.info("[DiscordLogHandler] Consumer task successfully cancelled.")
             except Exception as e:
                  logging.error(f"[DiscordLogHandler] Error during consumer task cancellation: {e}", exc_info=True)
        logging.info("[DiscordLogHandler] Handler closed.")

    def close(self):
        """동기적 로깅 종료 시 호출됩니다. 비동기 종료 로직을 실행합니다."""
        if self.loop.is_running():
             # 이벤트 루프가 실행 중일 때만 비동기 종료 호출
             self.loop.create_task(self.close_async())
        super().close()

# --- 핸들러 설정 및 로거에 추가 ---
discord_handler: Optional[DiscordLogHandler] = None # 핸들러 인스턴스 저장용 전역 변수

# 이 함수는 RemoveServerModal의 on_submit 또는 RemoveServerButton의 콜백에서 호출되어야 합니다.
# 함수 시그니처에 reason_provided 추가
async def remove_server_config(interaction: discord.Interaction, guild_id_str: str, reason_provided: str):
    log_prefix = f"[RemoveServerCmd User {interaction.user.id} Target Guild {guild_id_str}]"
    logging.info(f"{log_prefix} Server removal command initiated.")

    followup = interaction.followup
    try:
        # Ensure deferral only happens if not already done (e.g., from modal submit)
        if not interaction.response.is_done():
            await interaction.response.defer(ephemeral=True, thinking=True)
    except discord.InteractionResponded:
        logging.warning(f"{log_prefix} Interaction already responded to. Using followup.")
        pass # Already deferred, continue

    if not guild_id_str.isdigit():
        logging.warning(f"{log_prefix} Invalid Guild ID format provided: {guild_id_str}")
        await followup.send(f"❌ 잘못된 길드 ID 형식입니다: `{guild_id_str}`. 숫자만 입력해주세요.", ephemeral=True)
        return

    # ---> 사유 포맷팅 및 _remove_server_config_logic 호출 수정 <---
    # 관리자가 입력한 사유에 추가 정보 결합
    final_reason = f"{reason_provided}"
    # 수정된 사유를 전달
    success, purge_results = await _remove_server_config_logic(guild_id_str, reason=final_reason)
    # --------------------------------------------------------

    if success:
        result_message = f"✅ 길드 ID `{guild_id_str}`의 서버 등록을 성공적으로 해제했습니다.\n\n**채널 정리 결과:**\n" + "\n".join(purge_results)
        await followup.send(result_message, ephemeral=True)
        logging.info(f"{log_prefix} Server removal process completed successfully via command.")
    else:
        result_message = f"❌ 길드 ID `{guild_id_str}` 서버 등록 해제 중 문제가 발생했습니다.\n\n**처리 결과:**\n" + "\n".join(purge_results)
        await followup.send(result_message, ephemeral=True)
        logging.error(f"{log_prefix} Server removal process failed via command.")

async def _remove_server_config_logic(guild_id_str: str, reason: str = "Unknown") -> Tuple[bool, List[str]]:
    log_prefix = f"[_RemoveServerLogic Guild {guild_id_str} Reason: {reason}]"
    logging.info(f"{log_prefix} Starting removal logic.")
    purge_results = []
    removal_success = False
    verify_channel_id_to_notify: Optional[int] = None
    # admin_channel_id_to_notify 제거
    log_channel_id_to_notify: Optional[int] = None

    if not guild_id_str.isdigit():
        logging.error(f"{log_prefix} Invalid Guild ID format provided.")
        purge_results.append("❌ 잘못된 길드 ID 형식.")
        return False, purge_results

    guild_id_int = int(guild_id_str)

    try:
        config_data = await asyncio.to_thread(load_config, CONFIG_FILE)

        if guild_id_str not in config_data:
            logging.warning(f"{log_prefix} Guild ID not found in config file. Nothing to remove.")
            purge_results.append(f"ℹ️ 설정 파일에서 길드 ID `{guild_id_str}`를 찾을 수 없음.")
            return True, purge_results

        guild_conf_to_remove = config_data[guild_id_str]
        verify_channel_id_to_notify = guild_conf_to_remove.get("verify_channel_id")
        # admin_channel_id_to_notify 제거
        log_channel_id_to_notify = guild_conf_to_remove.get("log_channel_id")

        target_guild = bot.get_guild(guild_id_int)
        if target_guild:
            logging.debug(f"{log_prefix} Attempting channel purge in guild '{target_guild.name}'.")

            verify_channel_id = guild_conf_to_remove.get("verify_channel_id")
            if verify_channel_id:
                verify_channel = target_guild.get_channel(verify_channel_id)
                if verify_channel and isinstance(verify_channel, discord.TextChannel):
                    try:
                        perms = verify_channel.permissions_for(target_guild.me)
                        if perms.read_message_history and perms.manage_messages:
                            await verify_channel.purge(limit=None); purge_results.append(f"✅ 인증 채널({verify_channel.mention}) 정리 완료.")
                        else: purge_results.append(f"⚠️ 인증 채널({verify_channel.mention}) 정리 실패 (권한 부족).")
                    except Exception as e_purge_v: purge_results.append(f"❌ 인증 채널({verify_channel.mention}) 정리 실패: {type(e_purge_v).__name__}"); logging.error(f"{log_prefix} Purge verify error: {e_purge_v}", exc_info=True)
                else: purge_results.append(f"ℹ️ 인증 채널({verify_channel_id}) 찾을 수 없음.")
            else: purge_results.append("ℹ️ 설정에 인증 채널 ID 없음.")

            # 관리자 채널 정리 로직 제거

            log_channel_id = guild_conf_to_remove.get("log_channel_id")
            if log_channel_id:
                log_channel = target_guild.get_channel(log_channel_id)
                if log_channel and isinstance(log_channel, discord.TextChannel):
                     try:
                        perms = log_channel.permissions_for(target_guild.me)
                        if perms.read_message_history and perms.manage_messages:
                            await log_channel.purge(limit=None); purge_results.append(f"✅ 로그 채널({log_channel.mention}) 정리 완료.")
                        else: purge_results.append(f"⚠️ 로그 채널({log_channel.mention}) 정리 실패 (권한 부족).")
                     except Exception as e_purge_l: purge_results.append(f"❌ 로그 채널({log_channel.mention}) 정리 실패: {type(e_purge_l).__name__}"); logging.error(f"{log_prefix} Purge log channel error: {e_purge_l}", exc_info=True)
                else: purge_results.append(f"ℹ️ 로그 채널({log_channel_id}) 찾을 수 없음.")
            else: purge_results.append("ℹ️ 설정에 로그 채널 ID 없음.")
        else:
            purge_results.append(f"⚠️ 봇이 길드({guild_id_str})에 없어 채널 정리 불가.")
            logging.warning(f"{log_prefix} Bot is not in the target guild.")

        async with CONFIG_LOCK:
            log_prefix_lock = f"{log_prefix} [ConfigLock]"
            current_config_data = await asyncio.to_thread(load_config, CONFIG_FILE)
            if guild_id_str in current_config_data:
                logging.debug(f"{log_prefix_lock} Removing guild entry from config data...")
                del current_config_data[guild_id_str]
                save_success = await asyncio.to_thread(save_config, current_config_data, CONFIG_FILE)
                if save_success:
                    logging.info(f"{log_prefix_lock} Successfully removed guild entry and saved config file.")
                    removal_success = True
                    await asyncio.to_thread(sync_guild_configs)
                    logging.info(f"{log_prefix_lock} In-memory config synced.")
                    # 관리자 채널 ID 제거
                    await send_removal_notification(guild_id_str, verify_channel_id_to_notify, reason)
                else:
                    logging.error(f"{log_prefix_lock} Failed to save updated config file after removing guild.")
                    purge_results.append("❌ 설정 파일 저장 실패!")
                    removal_success = False
            else:
                 logging.warning(f"{log_prefix_lock} Guild ID already removed from config, likely by another process.")
                 removal_success = True

        return removal_success, purge_results

    except FileNotFoundError:
        logging.error(f"{log_prefix} Config file not found.")
        purge_results.append("❌ 설정 파일을 찾을 수 없음.")
        return False, purge_results
    except Exception as e:
        logging.error(f"{log_prefix} An unexpected error occurred: {e}", exc_info=True)
        purge_results.append(f"⚙️ 처리 중 예상치 못한 오류 발생: {type(e).__name__}")
        return False, purge_results
            
# admin_channel_id 파라미터 제거
async def send_removal_notification(guild_id: str, verify_channel_id: Optional[int], reason: str):
    log_prefix = f"[RemovalNotify Guild {guild_id}]"
    logging.info(f"{log_prefix} Attempting to send removal notification with re-register button. Reason: {reason}")

    embed = discord.Embed(
        title="❗ 서버 등록 해제 알림",
        description=f"이 서버의 봇 설정이 제거되었습니다.",
        color=discord.Color.red(),
        timestamp=datetime.now()
    )
    embed.add_field(name="사유", value=f"```\n{reason}\n```", inline=False)
    embed.set_footer(text="더 이상 해당 서버에서 봇 기능이 작동하지 않습니다.")

    view = discord.ui.View()
    view.add_item(discord.ui.Button(
        label="재등록하기",
        style=discord.ButtonStyle.link,
        url="https://discord.com/invite/RJk8C4Ungh",
        emoji="🔄"
    ))

    channels_to_notify: List[Optional[discord.TextChannel]] = []
    if verify_channel_id:
        channels_to_notify.append(bot.get_channel(verify_channel_id))
    # 관리자 채널 추가 로직 제거

    sent_count = 0
    for channel in channels_to_notify: # 이제 verify_channel만 있거나 비어있음
        if channel and isinstance(channel, discord.TextChannel):
            try:
                guild = channel.guild
                if guild:
                    perms = channel.permissions_for(guild.me)
                    if perms.send_messages and perms.embed_links:
                        await channel.send(embed=embed, view=view)
                        logging.info(f"{log_prefix} Sent notification to channel #{channel.name} ({channel.id}).")
                        sent_count += 1
                    else:
                        logging.warning(f"{log_prefix} Cannot send notification to #{channel.name}: Missing Send/Embed permission.")
                else:
                    logging.warning(f"{log_prefix} Cannot send notification: Channel {channel.id} is not in a guild.")

            except discord.Forbidden:
                logging.error(f"{log_prefix} Cannot send notification to #{channel.name}: Forbidden.")
            except discord.NotFound:
                logging.warning(f"{log_prefix} Cannot send notification: Channel {channel.id} not found.")
            except Exception as e:
                logging.error(f"{log_prefix} Failed to send notification to #{channel.name}: {e}", exc_info=True)
        elif channel is None:
             # 이 경우는 verify_channel_id가 잘못된 경우만 해당
             logging.warning(f"{log_prefix} Cannot send notification: Verify Channel ID {verify_channel_id} not found by bot.")

    logging.info(f"{log_prefix} Finished sending notifications (Sent: {sent_count}/{len(channels_to_notify)}).")

async def cleanup_expired_serials():
    log_prefix = "[SerialCleanup]"
    logging.info(f"{log_prefix} Starting scheduled check for expired serial codes...")
    valid_date_format = "%Y-%m-%d"
    file_changed = False

    try:
        async with SERIAL_LOCK:
            log_prefix_lock = f"{log_prefix} [Lock]"
            logging.debug(f"{log_prefix_lock} Acquired serial lock.")

            serials_map = await asyncio.to_thread(load_serials, SERIAL_FILE)

            if not serials_map:
                logging.info(f"{log_prefix_lock} No serial codes found to check.")
                logging.debug(f"{log_prefix_lock} Releasing serial lock (no codes).")
                return

            today = date.today()
            valid_serials_map = {}
            expired_count = 0

            # serials_map은 이제 {code: {"expires_at": ..., "rank": ...}} 형태임
            for code, serial_info in serials_map.items():
                expires_at_str = serial_info.get("expires_at")
                rank = serial_info.get("rank") # rank 정보도 가져옴 (필요시 사용)

                if not expires_at_str:
                    logging.warning(f"{log_prefix_lock} Serial code '{code[:4]}...' missing expiration date. Keeping it.")
                    valid_serials_map[code] = serial_info # 일단 유지
                    continue

                try:
                    expires_date = datetime.strptime(expires_at_str, valid_date_format).date()
                    if expires_date < today:
                        logging.info(f"{log_prefix_lock} Serial code '{code[:4]}...' expired (Expired date: {expires_at_str}). Marked for removal.")
                        expired_count += 1
                        file_changed = True
                    else:
                        valid_serials_map[code] = serial_info # 유효하면 유지
                except ValueError:
                    logging.warning(f"{log_prefix_lock} Invalid date format '{expires_at_str}' for serial code '{code[:4]}...'. Keeping it for now.")
                    valid_serials_map[code] = serial_info # 일단 유지

            if file_changed:
                logging.info(f"{log_prefix_lock} Found {expired_count} expired serial codes. Saving updated list...")
                save_success = await asyncio.to_thread(save_serials, valid_serials_map, SERIAL_FILE)
                if save_success:
                    logging.info(f"{log_prefix_lock} Successfully removed {expired_count} expired serial codes and saved the file.")
                else:
                    logging.error(f"{log_prefix_lock} Failed to save the serial file after removing expired codes!")
            else:
                logging.info(f"{log_prefix_lock} No expired serial codes found requiring removal in this check.")

            logging.debug(f"{log_prefix_lock} Releasing serial lock.")

    except asyncio.TimeoutError:
        logging.error(f"{log_prefix} Timeout acquiring serial lock.")
    except Exception as e:
        logging.error(f"{log_prefix} Unexpected error during serial cleanup loop: {e}", exc_info=True)

@bot.tree.command(name="사용자확인", description="DB에 저장된 사용자 정보를 확인합니다. (관리자 전용)")
@app_commands.describe(user_id="확인할 사용자의 Discord ID")
@app_commands.checks.has_permissions(administrator=True)
async def check_user_command(interaction: discord.Interaction, user_id: str):
    guild = interaction.guild
    if not guild:
        await interaction.response.send_message("❌ 이 명령어는 서버 내에서만 사용할 수 있습니다.", ephemeral=True)
        return

    guild_id_str = str(guild.id)
    log_prefix = f"[/사용자확인 Cmd Guild {guild_id_str} User {interaction.user.id}]"
    logging.info(f"{log_prefix} Command invoked by user with admin permissions.")

    if not user_id.isdigit():
        await interaction.response.send_message("❌ 사용자 ID는 숫자 형식이어야 합니다.", ephemeral=True)
        return
    if not (17 <= len(user_id) <= 20): # Discord ID 길이 범위 체크
        await interaction.response.send_message(f"❌ 유효하지 않은 사용자 ID 길이입니다: {len(user_id)}", ephemeral=True)
        return

    await check_user(interaction, user_id)

@check_user_command.error
async def check_user_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    if isinstance(error, app_commands.MissingPermissions):
        await interaction.response.send_message("❌ 이 명령어를 사용하려면 서버 관리자 권한이 필요합니다.", ephemeral=True)
    else:
        logging.error(f"Unhandled error in /사용자확인 command: {error}", exc_info=error)
        try:
             if not interaction.response.is_done():
                 await interaction.response.send_message("⚙️ 명령어 처리 중 오류가 발생했습니다.", ephemeral=True)
             else:
                  await interaction.followup.send("⚙️ 명령어 처리 중 오류가 발생했습니다.", ephemeral=True)
        except Exception as e_resp:
            logging.error(f"Failed to send error message for /사용자확인: {e_resp}")

@bot.event
async def on_ready():
    global discord_handler, webhook_server_running
    logging.info(f">>> on_ready event handler triggered (Bot ID: {bot.user.id})! Re-checking initializations...")
    print(f"\n✅ Bot '{bot.user}' connected/reconnected!")

    if not hasattr(bot, 'background_tasks_initialized'):
        bot.background_tasks_initialized = True
        bot.cleanup_serial_task_handle = None
        bot.automated_token_task_handle = None
        bot.expired_server_task_handle = None
        bot.config_observer = None
        bot.daily_tasks_started = False # 새 플래그 추가
        print("[on_ready] Initializing background task handles on bot object.")

    try:
        logging.info(">>> Initializing database (if needed)...")
        await init_db()
        print("✅ Database checked/initialized.")
        logging.info("✅ Database checked/initialized.")

        logging.info(">>> Syncing slash commands...")
        await bot.tree.sync()
        print("✅ Slash commands synced.")
        logging.info("✅ Slash commands synced.")

        logging.info(">>> Loading initial guild configs...")
        await asyncio.to_thread(sync_guild_configs)
        print(f"✅ Initial guild configs loaded/synced: {len(guild_configs)} guilds")
        logging.info(f"✅ Initial guild configs synced: {len(guild_configs)} guilds found.")

        if bot.config_observer is None or not bot.config_observer.is_alive():
            logging.info(">>> Starting watchdog observer...")
            loop = asyncio.get_running_loop()
            event_handler = ConfigChangeEventHandler(loop)
            observer = Observer()
            observer.schedule(event_handler, path=BASE_DIR, recursive=False)
            try:
                observer.start()
                bot.config_observer = observer
                logging.info(f"Config file watcher started. Monitoring directory: {BASE_DIR} for {os.path.basename(CONFIG_FILE)}")
                print(f"✅ Config file watcher started (monitoring {BASE_DIR} for {os.path.basename(CONFIG_FILE)}).")
            except Exception as e_obs:
                logging.error(f"Failed to start watchdog observer: {e_obs}", exc_info=True)
                print(f"❌ Failed to start watchdog observer: {e_obs}")
                bot.config_observer = None
        else:
            logging.info(">>> Watchdog observer already running.")
            print("ℹ️ Watchdog observer already running.")

        logging.info(">>> Setting up webhook server (if not running)...")
        try:
            # webhook_started 변수 제거 (바로 사용 안 함)
            await setup_webhook_server(bot)
            # webhook_server_running 플래그로 시작 여부 판단
            if not webhook_server_running:
                 raise RuntimeError("Webhook server setup failed but did not raise exception.")
        except Exception as e_webhook_setup:
             logging.critical(f"CRITICAL error during webhook server setup in on_ready: {e_webhook_setup}", exc_info=True)
             print(f"❌ CRITICAL error during webhook server setup: {e_webhook_setup}")
             await bot.close()
             return

        if discord_handler is None and ADMIN_LOG_CHANNEL_ID:
            logging.info(f">>> Setting up Discord logging to channel ID: {ADMIN_LOG_CHANNEL_ID}")
            try:
                log_channel_check = bot.get_channel(ADMIN_LOG_CHANNEL_ID)
                if log_channel_check and isinstance(log_channel_check, discord.TextChannel):
                    current_loop = asyncio.get_running_loop()
                    discord_handler = DiscordLogHandler(bot, ADMIN_LOG_CHANNEL_ID, current_loop)
                    log_format = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
                    date_format = '%Y-%m-%d %H:%M:%S'
                    formatter = logging.Formatter(log_format, date_format)
                    discord_handler.setFormatter(formatter)
                    discord_handler.setLevel(logging.WARNING)
                    logging.getLogger().addHandler(discord_handler)
                    logging.info(f"✅ Discord logging handler added. Logs >= WARNING will be sent to #{log_channel_check.name}.")
                else:
                    logging.error(f"ADMIN_LOG_CHANNEL_ID {ADMIN_LOG_CHANNEL_ID} is invalid or bot cannot access it. Discord logging disabled.")
                    print(f"❌ Invalid Discord log channel ID: {ADMIN_LOG_CHANNEL_ID}. Discord logging disabled.")
            except Exception as e_log_setup:
                 logging.error(f"Failed to setup Discord logging handler: {e_log_setup}", exc_info=True)
                 print(f"❌ Error setting up Discord logging: {e_log_setup}")
        elif discord_handler:
             logging.info(">>> Discord logging handler already configured.")
             print("ℹ️ Discord logging handler already configured.")
        else:
            logging.warning("ADMIN_LOG_CHANNEL_ID not set. Discord logging disabled.")
            print("⚠️ ADMIN_LOG_CHANNEL_ID not set. Discord logging disabled.")

        logging.info(">>> Initializing guilds (Verification channels only)...") # 로그 메시지 수정
        processed_guild_count = 0
        for guild_id_str in list(guild_configs.keys()):
             guild = bot.get_guild(int(guild_id_str))
             if not guild:
                logging.warning(f"on_ready: Guild {guild_id_str} not found in bot's guilds, skipping initialization.")
                continue
             await send_verification_message(guild_id_str)
             # 관리자 채널 메시지 전송 로직 제거
             processed_guild_count += 1
             logging.debug(f"Guild verification message initialization triggered for {guild_id_str}.")
        logging.info(f"✅ Guild verification messages sent/checked for {processed_guild_count} configured guilds.") # 로그 메시지 수정

        logging.info(">>> Deploying Super Admin View...")
        if ADMIN_CONTROL_CHANNEL_ID:
            super_admin_channel = bot.get_channel(ADMIN_CONTROL_CHANNEL_ID)
            if super_admin_channel and isinstance(super_admin_channel, discord.TextChannel):
                try:
                    sac_guild = super_admin_channel.guild
                    if sac_guild:
                        perms = super_admin_channel.permissions_for(sac_guild.me)
                        if perms.read_message_history and perms.manage_messages:
                             await super_admin_channel.purge(limit=100)
                        if perms.send_messages and perms.embed_links:
                             super_embed = discord.Embed(title="🛠️ 총괄 관리자 뷰", description="DB 직접 조회 등 개발자 전용 기능입니다.", color=discord.Color.dark_gold())
                             await super_admin_channel.send(embed=super_embed, view=SuperAdminView())
                             print(f"✅ Super Admin view deployed/updated to channel ID: {ADMIN_CONTROL_CHANNEL_ID}")
                             logging.info(f"✅ Super Admin view deployed/updated to {super_admin_channel.name}")
                        else:
                             print(f"❌ Failed to deploy Super Admin view: Missing Send/Embed permission in channel {ADMIN_CONTROL_CHANNEL_ID}.")
                             logging.error(f"Cannot send/embed in Super Admin channel {ADMIN_CONTROL_CHANNEL_ID}.")
                    else:
                         print(f"❌ Cannot deploy Super Admin view: Channel {ADMIN_CONTROL_CHANNEL_ID} is not in a guild.")
                         logging.error(f"Super Admin channel {ADMIN_CONTROL_CHANNEL_ID} is not in a guild.")
                except Exception as e_super_admin:
                     print(f"❌ Error deploying Super Admin view to channel {ADMIN_CONTROL_CHANNEL_ID}: {e_super_admin}")
                     logging.error(f"Super Admin channel message error ({ADMIN_CONTROL_CHANNEL_ID}): {e_super_admin}", exc_info=True)
            else:
                print(f"⚠️ Super Admin channel ID {ADMIN_CONTROL_CHANNEL_ID} not found or is not a TextChannel.")
                logging.warning(f"Super Admin channel {ADMIN_CONTROL_CHANNEL_ID} not found/invalid.")
        else:
            print("⚠️ ADMIN_CONTROL_CHANNEL_ID not set. Super Admin View not deployed.")
            logging.warning("ADMIN_CONTROL_CHANNEL_ID not set. Super Admin View not deployed.")

        # --- ★★★ 기존 tasks.loop 시작 코드 제거 및 새 스케줄링 로직 추가 ★★★ ---
        logging.info(">>> Starting/Scheduling background tasks...")

        # Automated Token Check (기존 tasks.loop 방식 유지 가능 또는 daily_task_runner로 변경 가능)
        if bot.automated_token_task_handle is None or bot.automated_token_task_handle.done():
             if ADMIN_LOG_CHANNEL_ID is not None:
                 if 'automated_token_check' in globals() and isinstance(globals()['automated_token_check'], tasks.Loop):
                     try:
                         bot.automated_token_task_handle = automated_token_check.start()
                         print(f"✅ Automated check task (tasks.loop) started ({automated_token_check.hours}h interval). Logging to channel {ADMIN_LOG_CHANNEL_ID}.")
                         logging.info(f"✅ Automated check task (tasks.loop) started ({automated_token_check.hours}h interval). Logging to channel ID: {ADMIN_LOG_CHANNEL_ID}")
                     except RuntimeError as e_task_start:
                         logging.warning(f"Could not start automated_token_check task: {e_task_start}")
                         print(f"⚠️ Could not start automated_token_check task: {e_task_start}")
                 else:
                     logging.error("Automated check task function missing or invalid.")
                     print("❌ Failed to start automated check: Task missing.")
             else:
                 print("⚠️ Automated check task NOT started: ADMIN_LOG_CHANNEL_ID is missing.")
                 logging.warning("Automated check task NOT started: ADMIN_LOG_CHANNEL_ID is missing.")
        else:
            print("ℹ️ Automated check task already running (checked via handle).")
            logging.warning("Automated_token_check task already running (checked via handle).")

        # Daily Tasks (Expired Servers & Serials) - 새 스케줄링 방식
        if not bot.daily_tasks_started:
            logging.info("Scheduling daily tasks (check_expired_servers, cleanup_expired_serials)...")
            # check_expired_servers 태스크 생성 (매일 00:01 실행)
            bot.expired_server_task_handle = asyncio.create_task(daily_task_runner(check_expired_servers, hour=0, minute=1))
            # cleanup_expired_serials 태스크 생성 (매일 00:05 실행)
            bot.cleanup_serial_task_handle = asyncio.create_task(daily_task_runner(cleanup_expired_serials, hour=0, minute=5))
            bot.daily_tasks_started = True
            print("✅ Daily tasks scheduled.")
            logging.info("✅ Daily tasks scheduled (check_expired_servers at 00:01, cleanup_expired_serials at 00:05).")
        else:
             print("ℹ️ Daily tasks already scheduled.")
             logging.info("Daily tasks already scheduled.")
        # --- ★★★ 변경 끝 ★★★ ---

        print("✅ Bot on_ready sequence completed!")
        logging.info("✅ Bot on_ready sequence fully completed!")

    except Exception as e:
        logging.critical(f"CRITICAL error during on_ready execution: {e}", exc_info=True)
        print(f"❌ CRITICAL error during bot startup in on_ready: {e}")
        if not bot.is_closed():
            await bot.close()

@bot.event
async def on_close():
    global discord_handler, webhook_server_running
    print("\n[on_close] Cleanup sequence initiated...")
    logging.info("Cleanup sequence initiated on bot close.")

    # --- ★★★ 취소할 태스크 목록 이름 변경 또는 유지 ★★★ ---
    # 태스크 핸들 변수 이름이 on_ready에서 설정한 것과 동일한지 확인
    tasks_to_cancel = {
        'cleanup_serial_task': getattr(bot, 'cleanup_serial_task_handle', None),
        'automated_token_task': getattr(bot, 'automated_token_task_handle', None),
        'expired_server_task': getattr(bot, 'expired_server_task_handle', None),
    }
    # --- ★★★ 확인 끝 ★★★ ---

    for name, task_handle in tasks_to_cancel.items():
        print(f"[on_close] Attempting to stop {name}...")
        if task_handle and not task_handle.done():
            task_handle.cancel()
            try:
                # asyncio.create_task로 생성된 태스크는 await으로 기다릴 수 있음
                await asyncio.wait_for(task_handle, timeout=5.0)
                print(f"[on_close] {name} cancelled successfully.")
                logging.info(f"{name} cancelled successfully.")
            except asyncio.CancelledError:
                print(f"[on_close] {name} cancellation confirmed.")
                logging.info(f"{name} cancellation confirmed.")
            except asyncio.TimeoutError:
                 print(f"[on_close] Timeout waiting for {name} to cancel.")
                 logging.warning(f"Timeout waiting for {name} to cancel.")
            except Exception as e:
                # Handle cases where awaiting a cancelled task might raise other exceptions
                print(f"[on_close] Error during {name} cancellation/await: {e}")
                logging.warning(f"Error during {name} cancellation/await: {e}")
        elif task_handle and task_handle.done():
             # 태스크가 이미 완료된 경우, 결과를 확인하여 예외 로깅 (선택적)
            try:
                 exception = task_handle.exception()
                 if exception:
                     logging.warning(f"Task {name} was already done but finished with exception: {exception}")
                     print(f"[on_close] Task {name} was done but had exception: {exception}")
                 else:
                     print(f"[on_close] {name} was already done.")
                     logging.info(f"{name} was already done.")
            except asyncio.InvalidStateError:
                 # 작업이 아직 결과/예외를 가지지 않는 매우 드문 경우
                 print(f"[on_close] {name} was done but in an invalid state.")
                 logging.warning(f"Task {name} was done but in an invalid state.")
        else:
            print(f"[on_close] {name} handle not found or was None.")
            logging.info(f"{name} handle not found or was None.")

    print("[on_close] Attempting to stop watchdog observer...")
    if hasattr(bot, 'config_observer') and bot.config_observer and bot.config_observer.is_alive():
        try:
            bot.config_observer.stop()
            bot.config_observer.join(timeout=5.0)
            if not bot.config_observer.is_alive():
                 print("[on_close] Watchdog observer stopped.")
                 logging.info("Watchdog observer stopped.")
            else:
                 print("[on_close] Timeout stopping watchdog observer thread.")
                 logging.warning("Timeout stopping watchdog observer thread.")
        except Exception as e_obs_stop:
             print(f"[on_close] Error stopping watchdog observer: {e_obs_stop}")
             logging.error(f"Error stopping watchdog observer: {e_obs_stop}", exc_info=True)
    else:
        print("[on_close] Watchdog observer not running or not found.")
        logging.info("Watchdog observer not running or not found.")

    print("[on_close] Attempting to close Discord log handler...")
    if discord_handler:
        try:
            await discord_handler.close_async()
            logging.getLogger().removeHandler(discord_handler)
            print("[on_close] Discord log handler closed and removed.")
            logging.info("Discord log handler closed and removed.")
        except Exception as e_close_handler:
            print(f"[on_close] Error closing Discord log handler: {e_close_handler}")
            logging.error(f"Error closing Discord log handler: {e_close_handler}", exc_info=True)
        finally:
             discord_handler = None
    else:
        print("[on_close] Discord log handler was not initialized.")

    print("[on_close] Attempting webhook server cleanup...")
    await cleanup_webhook_server(bot)

    print("[on_close] Attempting to close aiohttp session...")
    if hasattr(bot, 'http_session') and bot.http_session and not bot.http_session.closed:
        await bot.http_session.close()
        await asyncio.sleep(0.25)
        if bot.http_session.closed:
            print("[on_close] aiohttp session closed.")
            logging.info("aiohttp session closed.")
        else:
            print("[on_close] Warning: aiohttp session did not close properly.")
            logging.warning("aiohttp session did not close properly.")
    elif hasattr(bot, 'http_session') and bot.http_session and bot.http_session.closed:
         print("[on_close] aiohttp session was already closed.")
         logging.info("aiohttp session was already closed.")
    else:
        print("[on_close] No active aiohttp session found or attached.")
        logging.info("No active aiohttp session found or attached.")

    print("[on_close] Cleanup finished.")
    logging.info("Bot cleanup finished.")

if __name__ == "__main__":
    # --- 시작 디버그 메시지 (터미널 출력용) ---
    print("[MainBlock] Starting script execution...")

    # --- Watchdog 라이브러리 임포트 확인 ---
    try:
        from watchdog.observers import Observer
        from watchdog.events import PatternMatchingEventHandler
        print("[MainBlock] Watchdog library imported successfully.")
    except ImportError:
        print("\n[MainBlock] Error: 'watchdog' library is required. Install using: pip install watchdog")
        logging.critical("Required library 'watchdog' not found. Install using: pip install watchdog")
        exit(1)

    # --- 로깅 설정 ---
    log_format = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    formatter = logging.Formatter(log_format, date_format)

    # 1. 루트 로거 가져오기
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG) # 전체 로거는 DEBUG 레벨 허용

    # 2. !!! 중요: 기존 핸들러 모두 제거 !!!
    if logger.hasHandlers():
        print("[MainBlock] Removing existing logging handlers...")
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
            handler.close()
        print(f"[MainBlock] Handlers removed. Current handlers: {logger.handlers}")
    else:
        print("[MainBlock] No existing logging handlers found on root logger.")

    # 3. 파일 핸들러 설정 및 추가
    try:
        file_handler = logging.FileHandler(LOG_FILE, mode='w', encoding='utf-8') # mode='w' 유지
        file_handler.setFormatter(formatter)
        # 파일 핸들러 레벨은 DEBUG 유지 (check_expired_servers 디버그 로그 보기 위함)
        file_handler.setLevel(logging.WARNING)
        logger.addHandler(file_handler)
        print(f"[MainBlock] File logging configured for: {LOG_FILE} (Level: DEBUG)") # 레벨 DEBUG 명시
        print(f"[MainBlock] FileHandler added. Current handlers: {logger.handlers}")
    except Exception as e:
        print(f"[MainBlock] Failed to configure file logging: {e}")
        # exit(1)

    # 4. 콘솔 핸들러는 추가하지 않음

    # ---> ★★★★★ 여기 수정: Watchdog 로거 레벨 설정 추가 ★★★★★ <---
    logging.getLogger('watchdog').setLevel(logging.INFO)
    # -----------------------------------------------------------------

    # 5. Discord 라이브러리 로그 레벨 조정
    logging.getLogger('discord').setLevel(logging.ERROR)
    print("[MainBlock] Discord library logger level set to ERROR.")
    print("[MainBlock] Watchdog library logger level set to INFO.") # 확인 메시지 추가

    # --- 로깅 설정 끝 ---
    # 로그 메시지 수정
    logging.info("Logging configured (File Only after handler cleanup). Watchdog/Discord levels adjusted.")

    # --- 메인 비동기 함수 정의 ---
    async def main():
        try:
            async with bot:
                await bot.start(BOT_TOKEN)
        except discord.LoginFailure:
            logging.critical("Discord Login Failure. Check BOT_TOKEN environment variable.")
            print("[MainBlock] ❌ Discord Login Failed. Check BOT_TOKEN.")
            raise
        except Exception as start_exc:
            logging.critical(f"Bot failed to start: {start_exc}", exc_info=True)
            print(f"[MainBlock] ❌ Bot failed to start: {start_exc}")
            raise

    # --- 메인 실행 블록 ---
    try:
        print("[MainBlock] Starting asyncio event loop with bot...")
        asyncio.run(main())
        print("[MainBlock] Asyncio event loop finished.")
    except KeyboardInterrupt:
        print("\n[MainBlock] KeyboardInterrupt caught. Exiting gracefully...")
        logging.warning("KeyboardInterrupt received. Initiating shutdown.")
    except discord.LoginFailure:
        pass
    except Exception as e:
        logging.critical(f"An unexpected top-level error occurred: {e}", exc_info=True)
        print(f"[MainBlock] ❌ An unexpected top-level error occurred: {e}")
    finally:
        print("[MainBlock] Script execution finished.")
        logging.info("Script execution finished.")
