import logging
from pymisp import PyMISP
import config

logger = logging.getLogger(__name__)


def get_misp() -> PyMISP:
    return PyMISP(config.MISP_URL, config.MISP_KEY, config.MISP_VERIFYCERT)
