import logging
from logging.config import fileConfig

fileConfig('config/logging.conf')
logger = logging.getLogger('web_tamper_protection')
