DEFAULT_TIMEOUT = 20

# ========== BASE URLS ==========
BASE_URL = "https://evolution.tecnoalarm.com"
HANDSHAKE_URL = f"{BASE_URL}/account/handshake"

# ========== ACCOUNT ENDPOINTS ==========
ACCOUNT_EMAIL_VALIDATION = "/email/{email}"
ACCOUNT_LOGIN = "/login"

# ========== TCS ENDPOINTS ==========
TCS_TP_REGISTER = "/tp"  # POST - register app with PIN
TCS_TP_DELETE = "/tp"  # DELETE - unregister
TCS_TP_STATUS_SSE = "/tpstatus/sse"  # GET - SSE sync status (called after POST /tp)
TCS_MONITOR = "/monitor/{tp_type}.{central_id}"  # GET - monitor status
TCS_TPS = "/tps"  # GET - list centrals
TCS_PROGRAM = "/program"  # GET - programs
TCS_PROGRAM_ARM = "/program/{program_idx}/{mode}"  # PUT - arm/disarm program
TCS_ZONE = "/zone"  # GET - zones
TCS_REMOTE = "/remote"  # GET - remotes
TCS_LOG = "/log/{from_id}"  # GET - logs
TCS_LOG_MEMORY_DELETE = "/tp/memory"  # DELETE - clear memory alarms
TCS_PUSH_COUNT = "/push/count"  # GET - push notification count
TCS_PUSH = "/push"  # GET - push notifications

# ========== HEADERS ==========
HDR_AUTH = "Auth"
HDR_APP_ID = "X-App-Id"
HDR_ATYPE = "atype"
HDR_TOKEN = "tcs-token"
HDR_LANG = "lang"
HDR_VER = "ver"

# ========== PROGRAM STATUS ==========
# Sistema Base (2 stati): 0 = disarmed/spento, 3 = armed/acceso
# Sistemi avanzati potrebbero supportare anche 1 (day) e 2 (night)
PROGRAM_STATUS = {
    0: "disarmed",
    1: "armed_day",      # Opzionale - non tutti i sistemi
    2: "armed_night",    # Opzionale - non tutti i sistemi
    3: "armed"           # Armato (stato principale ON)
}

# ========== CENTRAL TYPE MAPPING ==========
# Maps central type code to model prefix
MODEL_PREFIX_MAP = {
    45: "tp888",
    38: "tp042"
}
# CLOSED = zona chiusa, sensore non attivato (normale)
# OPEN = zona aperta, sensore attivato (es. movimento rilevato)

# ========== ZONE STATUS ==========
ZONE_STATUS = {
    "CLOSED": "closed",
    "OPEN": "open",
}

# ========== ERROR CODES ==========
HTTP_412_PRECONDITION_FAILED = 412  # PIN required/invalid
HTTP_401_UNAUTHORIZED = 401
HTTP_404_NOT_FOUND = 404
HTTP_207_MULTI_STATUS = 207  # Email exists