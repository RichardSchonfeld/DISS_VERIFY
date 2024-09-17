from pathlib import Path
import os
import django_heroku
import dj_database_url

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'django-insecure-#your_secret_key_here'
SHAMIR_ENC_SYMM_KEY = os.getenv('SHAMIR_ENC_SYMM_KEY')
DEBUG = True
#ALLOWED_HOSTS = ['verify-119c36994002.herokuapp.com/']
ALLOWED_HOSTS = ['*']

SECURE_SSL_REDIRECT = False
#SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')


INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'corsheaders',
    'Verify_app',
    'rest_framework',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

CORS_ALLOWED_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

ROOT_URLCONF = 'VerifyDjango.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'VerifyDjango.wsgi.application'


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / "db.sqlite3",
    }
}


#DATABASES = {
#    'default': dj_database_url.config(conn_max_age=600)
#}

AUTH_USER_MODEL = 'Verify_app.CustomUser'
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_DIRS = [BASE_DIR / "static"]
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

django_heroku.settings(locals())

# Infura API variables
INFURA_TEST_URL = 'https://sepolia.infura.io/v3/'
if os.getenv('INFURA_NETWORK_ID'):
    INFURA_TEST_URL = 'https://sepolia.infura.io/v3/' + os.getenv('INFURA_NETWORK_ID')
INFURA_API_KEY = os.getenv('INFURA_API_KEY')
INFURA_API_SECRET = os.getenv('INFURA_API_KEY_SECRET')

LOCAL_TEST_URL = 'http://localhost:8545'

WEB3_URL = 'https://eth-sepolia.g.alchemy.com/v2/aYWWiwfNOVekgXAEAKCgLB7qPpmRLCkS'


# Ensuring presence of vars loaded
#if not all([INFURA_API_KEY, INFURA_API_SECRET]):
    #raise ValueError("Infura API credentials not set properly in environ settings")

#if not INFURA_API_KEY:
#    raise ValueError("Infura API key (INFURA_PROJECT_ID) is not set properly in environment settings.")
#if not INFURA_API_SECRET:
#    raise ValueError("Infura API secret (INFURA_PROJECT_SECRET) is not set properly in environment settings.")

IPFS_PIN_ENDPOINT = 'https://api.pinata.cloud/pinning/pinFileToIPFS'
IPFS_GET_ENDPOINT = 'https://gateway.pinata.cloud/ipfs/'
PINATA_JWT = os.getenv('PINATA_JWT')

TATUM_API_KEY = os.getenv('TATUM_API_KEY')
TATUM_SECRET = os.getenv('TATUM_SECRET')

#CHAIN_ID = '11155111'
CHAIN_ID = '1337'

# Some profile config
SERVER_OP_ACC_ADDRESS = os.getenv('SERVER_OP_ACC_ADDRESS')

ETHEREUM_NODE_URL = 'http://localhost:8545'
#CONTRACT_ADDRESS = '0x87B4AAba7c69BB9880914Ddfa0bc25d401480d3d'
# og local : CONTRACT_ADDRESS = '0x1D6f99685c0a3Db81FA3C9F7A148CC61e54a1809'
# Sepolia contract addr old 0xC4331f728306632F130E7C14e09d62b9ca0788fA
# Sepolia new contract addr :
CONTRACT_ADDRESS = '0xf9279ee3822a8AA68E384fC688E129fCB896fE6f'
PUBLIC_KEY = '0x5b5E779329cA0166Bc90CF3A5e54bcC465974588'
PRIVATE_KEY = os.getenv('DAPP_PRIVATE_KEY')
