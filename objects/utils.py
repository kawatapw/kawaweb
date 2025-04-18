# -*- coding: utf-8 -*-

from typing import Optional
from typing import TYPE_CHECKING

from cmyui.logging import Ansi
from cmyui.logging import log
from pathlib import Path
from quart import render_template
from quart import session, g, jsonify

from objects import glob
from objects import utils

if TYPE_CHECKING:
    from PIL.Image import Image

# Logging Imports
import logging, os, yaml, json, logging.config, datetime, inspect, traceback, re, sys, time
import structlog, jsons, orjson, rapidjson
from logging import Handler
from datetime import datetime, date
from enum import IntEnum
from collections.abc import Mapping
from pythonjsonlogger import jsonlogger
from elasticsearch import Elasticsearch
from structlog.stdlib import NAME_TO_LEVEL

import functools, asyncio

# Dreaded Serialization Imports
import decimal


async def flash(status: str, msg: str, template: str) -> str:
    """Flashes a success/error message on a specified template."""
    return await render_template(f"{template}.html", flash=msg, status=status)


async def flash_with_customizations(status: str, msg: str, template: str) -> str:
    """Flashes a success/error message on a specified template. (for customisation settings)"""
    profile_customizations = utils.has_profile_customizations(
        session["user_data"]["id"]
    )
    return await render_template(
        template_name_or_list=f"{template}.html",
        flash=msg,
        status=status,
        customizations=profile_customizations,
    )


def get_safe_name(name: str) -> str:
    """Returns the safe version of a username."""
    # Safe name should meet few criterias.
    # - Whole name should be lower letters.
    # - Space must be replaced with _
    return name.lower().replace(" ", "_")


def convert_mode_int(mode: str) -> Optional[int]:
    """Converts mode (str) to mode (int)."""
    if mode not in _str_mode_dict:
        print("invalid mode passed into utils.convert_mode_int?")
        return
    return _str_mode_dict[mode]


_str_mode_dict = {"std": 0, "taiko": 1, "catch": 2, "mania": 3}


def convert_mode_str(mode: int) -> Optional[str]:
    """Converts mode (int) to mode (str)."""
    if mode not in _mode_str_dict:
        print("invalid mode passed into utils.convert_mode_str?")
        return
    return _mode_str_dict[mode]


_mode_str_dict = {0: "std", 1: "taiko", 2: "catch", 3: "mania"}


async def fetch_geoloc(ip: str) -> str:
    """Fetches the country code corresponding to an IP."""
    url = f"http://ip-api.com/line/{ip}"

    async with glob.http.get(url) as resp:
        if not resp or resp.status != 200:
            if glob.config.debug:
                log("Failed to get geoloc data: request failed.", Ansi.LRED)
            return "xx"
        status, *lines = (await resp.text()).split("\n")
        if status != "success":
            if glob.config.debug:
                log(f"Failed to get geoloc data: {lines[0]}.", Ansi.LRED)
            return "xx"
        return lines[1].lower()


async def validate_captcha(data: str) -> bool:
    """Verify `data` with hcaptcha's API."""
    url = f"https://hcaptcha.com/siteverify"

    request_data = {"secret": glob.config.hCaptcha_secret, "response": data}

    async with glob.http.post(url, data=request_data) as resp:
        if not resp or resp.status != 200:
            if glob.config.debug:
                log("Failed to verify captcha: request failed.", Ansi.LRED)
            return False

        res = await resp.json()

        return res["success"]


TIME_ORDER_SUFFIXES = ["nsec", "μsec", "msec", "sec"]


def magnitude_fmt_time(nanosec: int | float) -> str:
    """
    Formats a time value in nanoseconds into a human-readable string representation.
    """
    suffix = None
    for suffix in TIME_ORDER_SUFFIXES:
        if nanosec < 1000:
            break
        nanosec /= 1000
    return f"{nanosec:.2f} {suffix}"


def get_required_score_for_level(level: int) -> float:
    if level <= 100:
        if level >= 2:
            return 5000 / 3 * (4 * (level**3) - 3 * (level**2) - level) + 1.25 * (
                1.8 ** (level - 60)
            )
        else:
            return 1.0  # Should be 0, but we get division by 0 below so set to 1
    else:
        return 26931190829 + 1e11 * (level - 100)


def get_level(totalScore: int) -> int:
    level = 1
    while True:
        # Avoid endless loops
        if level > 120:
            return level

        # Calculate required score
        reqScore = get_required_score_for_level(level)

        # Check if this is our level
        if totalScore <= reqScore:
            # Our level, return it and break
            return level - 1
        else:
            # Not our level, calculate score for next level
            level += 1


BANNERS_PATH = Path.cwd() / ".data/banners"
BACKGROUND_PATH = Path.cwd() / ".data/backgrounds"


def has_profile_customizations(user_id: int = 0) -> dict[str, bool]:
    # check for custom banner image file
    for ext in ("jpg", "jpeg", "png", "gif"):
        path = BANNERS_PATH / f"{user_id}.{ext}"
        if has_custom_banner := path.exists():
            break
    else:
        has_custom_banner = False

    # check for custom background image file
    for ext in ("jpg", "jpeg", "png", "gif"):
        path = BACKGROUND_PATH / f"{user_id}.{ext}"
        if has_custom_background := path.exists():
            break
    else:
        has_custom_background = False

    return {"banner": has_custom_banner, "background": has_custom_background}


def crop_image(image: "Image") -> "Image":
    width, height = image.size
    if width == height:
        return image

    offset = int(abs(height - width) / 2)

    if width > height:
        image = image.crop([offset, 0, width - offset, height])
    else:
        image = image.crop([0, offset, width, height - offset])

    return image


### Logging Utils ###
class klogging:
    """
    Kawata Logging utilities for the application.
    """

    class Ansi(IntEnum):
        """
        ANSI escape codes for terminal colors.
        """

        # Default colours
        BLACK = 30
        RED = 31
        GREEN = 32
        YELLOW = 33
        BLUE = 34
        MAGENTA = 35
        CYAN = 36
        WHITE = 37

        # Light colours
        GRAY = 90
        LRED = 91
        LGREEN = 92
        LYELLOW = 93
        LBLUE = 94
        LMAGENTA = 95
        LCYAN = 96
        LWHITE = 97

        RESET = 0

        def __repr__(self) -> str:
            return f"\x1b[{self.value}m"

    def printf(
        msg: str, color: Optional[Ansi] = None, file_path: Optional[str] = None
    ) -> None:
        """
        Prints the message to console with color and saves to a file if path is specified.\n
        Used for debugging when logging is not available.
        """

        if color is not None:
            msg = f"{color}{msg}{klogging.Ansi.RESET}"
        print(msg)

        if file_path is not None:
            if not os.path.exists(file_path):
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "a") as file:
                file.write(msg + "\n")

    @staticmethod
    def setup_logging(
        default_path="logging.yaml", default_level=logging.INFO, env_key="LOG_CFG"
    ):
        path = default_path
        value = os.getenv(env_key, None)
        if value:
            path = value
        if os.path.exists(path):
            with open(path, "rt") as f:
                config = yaml.safe_load(f.read())
            logging.config.dictConfig(config)
        else:
            logging.basicConfig(level=default_level)

    @staticmethod
    def setup_structlog():
        """
        Configures the structlog logger with the desired processors and settings.

        This method sets up the structlog logger by configuring the processors,
        context class, logger factory, wrapper class, and cache logger settings.

        Processors:
        - filter_by_level: Filters log entries based on the log level.
        - add_logger_name: Adds the logger name to the log entry.
        - add_log_level: Adds the log level to the log entry.
        - PositionalArgumentsFormatter: Formats log entries with positional arguments.
        - TimeStamper: Adds a timestamp to the log entry.
        - StackInfoRenderer: Renders stack information for the log entry.
        - format_exc_info: Formats exception information for the log entry.
        - UnicodeDecoder: Decodes log entries with Unicode characters.
        - render_to_log_kwargs: Renders log entries to keyword arguments.

        Context Class: dict
        - The context class used for storing log context information.

        Logger Factory: structlog.stdlib.LoggerFactory
        - The logger factory used to create loggers.

        Wrapper Class: structlog.stdlib.BoundLogger
        - The wrapper class used to bind loggers to the current context.

        Cache Logger on First Use: True
        - Whether to cache the logger on first use.

        """
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.stdlib.render_to_log_kwargs,
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )

    @staticmethod
    def configure_logging():
        klogging.setup_logging()
        klogging.setup_structlog()

    class logLevel(IntEnum):
        """
        Represents the log levels for Pythons Built in logger.

        DEBUG (10): Detailed information, typically useful only for diagnosing problems.
        VERBOSE (11): Detailed information, typically useful only for diagnosing problems.
        INFO (20): General information about the execution of the program.
        WARNING (30): Indicates a potential issue or something that should be brought to attention.
        ERROR (40): Indicates a more serious problem that prevented the program from functioning.
        CRITICAL (50): Indicates a critical error that may cause the program to terminate.

        """

        DEBUG = 10
        VERBOSE = 11
        DBGLV2 = 14
        DBGLV1 = 16
        INFO = 20
        WARNING = 30
        ERROR = 40
        CRITICAL = 50

        def __repr__(self) -> str:
            return f"\x1b[{self.value}m"

        @classmethod
        def add_Log_Levels(cls):
            """
            Adds custom log levels to the logging module and structlog's NAME_TO_LEVEL dictionary.
            """
            logging.addLevelName(cls.VERBOSE, "VERBOSE")
            logging.addLevelName(cls.DBGLV2, "DBGLV2")
            logging.addLevelName(cls.DBGLV1, "DBGLV1")
            # Add the custom log levels to the NAME_TO_LEVEL dictionary in structlog
            NAME_TO_LEVEL["verbose"] = cls.VERBOSE
            NAME_TO_LEVEL["dbglv2"] = cls.DBGLV2
            NAME_TO_LEVEL["dbglv1"] = cls.DBGLV1

    logLevel.add_Log_Levels()

    class AnsiFuncs:
        ANSI_ESCAPE_REGEX = re.compile(r"(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]")

        def escape_ansi(line: str) -> str:
            return klogging.AnsiFuncs.ANSI_ESCAPE_REGEX.sub("", line)

    def log(
        msg: str,
        start_color: Ansi = None,
        extra: Optional[Mapping[str, object]] = None,
        logger: str = "",
        level: int = logging.INFO,
    ) -> None:
        """\
        A modified wrapper around the stdlib logging module to handle 
        backwards-compatibility for colours and adding extra fields to log records.\n
        Original Description:
            A thin wrapper around the stdlib logging module to handle mostly
            backwards-compatibility for colours during our migration to the
            standard library logging module.
        
        Args:
            msg: The message to log.
            start_color: The color to start the message with.
            extra: A dictionary of extra fields to add to the log record.
            logger: The name of the logger to use.
            level: The log level to use.
            exc_info: Whether to include exception information in the log record.

        Returns:
            None
        
        Raises:
            None
        """

        # Get the logger
        if logger:
            log_obj = logging.getLogger(logger)
        else:
            if start_color is klogging.Ansi.LYELLOW or level == 30:
                log_obj = logging.getLogger("console.warn")
            elif start_color is klogging.Ansi.LRED or level == 40:
                log_obj = logging.getLogger("console.error")
            else:
                if level:
                    if level <= 19:
                        log_obj = logging.getLogger("console.debug")
                    else:
                        log_obj = logging.getLogger("console.info")
                else:
                    log_obj = logging.getLogger("console.info")

        if level == logging.INFO:
            if start_color is klogging.Ansi.LYELLOW:
                log_level = logging.WARNING
            elif start_color is klogging.Ansi.LRED:
                log_level = logging.ERROR
            else:
                log_level = logging.INFO
        else:
            log_level = level

        # TODO: decouple colors from the base logging function; move it to
        # be a formatter-specific concern such that we can log without color.
        if glob.config.LOG_WITH_COLORS:
            color_prefix = f"{start_color!r}" if start_color is not None else ""
            color_suffix = f"{Ansi.RESET!r}" if start_color is not None else ""
        else:
            msg = klogging.AnsiFuncs.escape_ansi(msg)
            color_prefix = color_suffix = ""

        # Get the frame that called this function
        frame = inspect.currentframe().f_back
        info = inspect.getframeinfo(frame)

        # Add Timestamp and Message to the 'extra' fields
        extra = extra or {}

        extra["@timestamp"] = datetime.now().isoformat()
        extra["Message"] = klogging.AnsiFuncs.escape_ansi(msg)

        # Get the arguments of the calling function
        arg_info = inspect.getargvalues(frame)

        msg = f"{color_prefix}{msg}{color_suffix}"

        # Check if 'msg' is a format string
        if "%" in msg:
            # If 'extra' is a dictionary, use it to format the string
            if isinstance(extra, dict):
                msg = msg % extra
            # If 'extra' is a list or tuple, ensure it has the correct length
            elif isinstance(extra, (list, tuple)) and len(extra) == msg.count("%"):
                msg = msg % extra

        # Create a LogRecord with the correct information
        record = logging.LogRecord(
            name=log_obj.name,
            level=log_level,
            pathname=info.filename,
            lineno=info.lineno,
            msg=msg,
            args=None,
            exc_info=None,
            func=info.function,
        )

        # Add the logger and methodname to the 'extra' fields
        extra["logger"] = log_obj
        extra["method_name"] = logging.getLevelName(record.levelno).lower()
        extra["service.name"] = glob.config.SERVICE_NAME
        extra["container.name"] = glob.config.CONTAINER_NAME

        if log_level >= 21:
            # Add calling function's arguments to the 'extra' fields
            extra["args"] = arg_info.args
            extra["varargs"] = arg_info.varargs
            extra["keywords"] = arg_info.keywords
            extra["locals"] = arg_info.locals
            extra["func"] = info.function
            # Add stack trace to the 'extra' fields
            stack_info = inspect.stack()
            serializable_stack = [
                {
                    "filename": frame.filename,
                    "lineno": frame.lineno,
                    "function": frame.function,
                    "code_context": frame.code_context,
                    "index": frame.index,
                }
                for frame in stack_info
            ]
            extra["stack_trace"] = json.dumps(traceback.format_stack())
            extra["stack"] = json.dumps(serializable_stack)

            if log_level >= 40:
                # Add the 'exc_info' to the 'extra' fields
                extra["verbose_stacktrace"] = {}
                if info.function in frame.f_globals:
                    extra["verbose_stacktrace"]["func_signature"] = str(
                        inspect.signature(frame.f_globals[info.function])
                    )
                    extra["verbose_stacktrace"]["func_source"] = inspect.getsource(
                        frame.f_globals[info.function]
                    )
                extra["verbose_stacktrace"]["exc_info"] = traceback.format_exc()
                extra["verbose_stacktrace"]["exc_type"] = str(sys.exc_info()[0])
                extra["verbose_stacktrace"]["exception"] = str(
                    traceback.format_exception(*sys.exc_info())
                )
                extra["verbose_stacktrace"]["exception_only"] = str(
                    traceback.format_exception_only(
                        sys.exc_info()[0], sys.exc_info()[1]
                    )
                )
                extra["verbose_stacktrace"]["error"] = str(sys.exc_info()[1])
                extra["verbose_stacktrace"]["error_traceback"] = str(
                    traceback.format_exc()
                )
                extra["verbose_stacktrace"]["error_stack"] = serializable_stack
                extra["verbose_stacktrace"]["error_locals"] = str(arg_info.locals)
                extra["verbose_stacktrace"]["error_args"] = str(arg_info.args)
                extra["verbose_stacktrace"]["error_varargs"] = str(arg_info.varargs)
                extra["verbose_stacktrace"]["error_keywords"] = str(arg_info.keywords)
                extra["verbose_stacktrace"]["error_message"] = msg
                extra["verbose_stacktrace"]["error_level"] = log_level

                extra["verbose_stacktrace"] = json.dumps(
                    extra["verbose_stacktrace"], indent=2
                )

        # Add the 'extra' fields to the '__dict__' attribute of the 'LogRecord' object
        for key, value in extra.items():
            record.__dict__[key] = value

        # Handle the record
        log_obj.handle(record)

    @staticmethod
    def serialize_record(record, seen=None):
        """
        Serializes a record object into a dictionary.\n
        Coded to handle serialization of all types of objects for sending logs to elasticsearch.\n
        Doesn't work that well atm.

        Args:
            record: The record object to be serialized.
            seen: A set to keep track of objects that have already been serialized to avoid circular references.

        Returns:
            A dictionary representing the serialized record.

        Raises:
            None.
        """
        if seen is None:
            seen = set()
        seen.add(id(record))

        def serialize(value):
            try:
                if isinstance(value, (datetime, datetime.date, datetime.time)):
                    return value.isoformat()
                elif isinstance(value, decimal.Decimal):
                    return float(value)
                elif isinstance(value, bytes):
                    return value.decode("utf-8")
                elif isinstance(value, (list, set, tuple)):
                    return [serialize(item) for item in value]
                elif isinstance(value, dict):
                    return {key: serialize(val) for key, val in value.items()}
                elif hasattr(value, "__dict__"):
                    if id(value) in seen:
                        return f"<Circular Reference: {type(value).__name__} id={id(value)}>"
                    else:
                        return Utils.serialize_record(value, seen)
            except:
                pass
            try:
                json_record = json.dumps(value)
                return json_record
            except:
                try:
                    # Try to serialize with orjson
                    serialized_record = orjson.dumps(value).decode()
                    return serialized_record
                except:
                    try:
                        # Try to serialize with rapidjson
                        serialized_record = rapidjson.dumps(value)
                        return serialized_record
                    except:
                        return str(value)

        serializable_record = {}
        for key, value in record.__dict__.items():
            serializable_record[key] = serialize(value)

        return serializable_record

    @staticmethod
    async def access_log(request, response):
        """
        Logs the access details of a request and response.

        Args:
            request: The request object.
            response: The response object.

        Returns:
            The response object.

        Raises:
            Exception: If there is an error while logging the access.

        """
        try:
            start_time = getattr(g, "start_time", None)
            time_elapsed = time.time() - start_time if start_time else None

            # Determine color based on status code
            status_code = response.status_code
            if status_code >= 300 and status_code < 400:
                status_color = (
                    klogging.Ansi.LYELLOW
                )  # Yellow for 3xx redirection statuses
            elif status_code >= 400 and status_code < 500:
                status_color = klogging.Ansi.LBLUE  # Blue for 4xx client error statuses
            elif status_code >= 500:
                status_color = klogging.Ansi.LRED  # Red for 5xx server error statuses
            else:
                status_color = klogging.Ansi.LGREEN  # Green for other statuses

            klogging.log(
                f'| {request.method} | {status_color!r}{response.status}{klogging.Ansi.RESET!r} | {request.path} | ({request.headers.get("Cf-Ipcountry")}) {request.headers.get("Cf-Connecting-Ip")} | {response.content_length} bytes | {str(magnitude_fmt_time(time_elapsed)) if time_elapsed else "Unknown"}',
                extra={
                    "Request": json.dumps(
                        {
                            "Method": str(request.method),
                            "URL": str(request.url),
                            "Request-Time": str(magnitude_fmt_time(time_elapsed))
                            if time_elapsed
                            else "Unknown",
                            "Query-Parameters": request.args.to_dict(),
                            "Headers": {
                                k: str(v) for k, v in dict(request.headers).items()
                            },
                            "Client-IP": str(
                                request.headers.get("X-Forwarded-For", "")
                            ),
                            "Client-Country": str(
                                request.headers.get("CF-IPCountry", "")
                            ),
                            "User-Agent": str(
                                request.headers.get("User-Agent", "Unknown")
                            ),
                            "Req-Info": getattr(g, "req_info", {}),
                        }
                    ),
                    "Response": json.dumps(
                        {
                            "Status-Code": str(response.status_code),
                            "Headers": {
                                k: str(v) for k, v in dict(response.headers).items()
                            },
                        }
                    ),
                },
            )
        except Exception as e:
            klogging.log(
                f"Failed to log access: {e}",
                start_color=klogging.Ansi.LRED,
                level=logging.ERROR,
                extra={
                    "CodeRegion": "Logging",
                    "Func": "klogging.access_log",
                    "error": f"{e}",
                    "traceback": str(traceback.format_exc()),
                },
            )

        return response


class BytesJsonFormatter(jsonlogger.JsonFormatter):
    """A custom formatter for logging records as JSON with byte encoding.

    This formatter extends the `jsonlogger.JsonFormatter` class and provides additional functionality
    for encoding log records as bytes.

    Attributes:
        datefmt (str): The format string for the timestamp in the log record.
        style (str): The style of the log record formatting.

    Coded for sending logs to Logstash. (Use json_lines codec in logstash config)
    Please use the `jsonlogger.JsonFormatter` class for general JSON logging.
    """

    def format(self, record):
        """Format the log record as a JSON string with byte encoding.

        Args:
            record (LogRecord): The log record to be formatted.

        Returns:
            bytes: The formatted log record as bytes.
        """
        # Convert only keys and values that are not of type str, int, float, bool, or None
        record.__dict__ = {
            str(k)
            if not isinstance(k, (str, int, float, bool, type(None)))
            else k: str(v)
            if not isinstance(v, (str, int, float, bool, type(None)))
            else v
            for k, v in record.__dict__.items()
        }

        # Check if the message contains any placeholders as this throws an error when formatting on string_record
        if not re.search(r"%\(.+?\)s", record.msg) and record.args:
            record.args = None

        string_record = super().format(record)
        return string_record.encode("utf-8") + b"\n"


class ElasticsearchHandler(Handler):
    """
    This is a custom logging handler that sends logs to an Elasticsearch instance.
    This is very WIP and not recommended for production use.
    It is recommended to use logstash or filebeat to send logs to Elasticsearch.

    Attributes:
        es: An Elasticsearch client instance.
        index: The name of the Elasticsearch index where logs will be stored.

    Problems:
        Doesn't handle serialization of all types of objects.
    """

    def __init__(self, hosts, index, *args, **kwargs):
        """
        Initialize the Elasticsearch handler.
        """
        super().__init__(*args, **kwargs)
        self.es = Elasticsearch(hosts)
        self.index = index

    def emit(self, record):
        """
        Emits a log record to Elasticsearch.

        Args:
            record (logging.LogRecord): The log record to be emitted.

        Raises:
            Exception: If the log record fails to serialize.

        """
        # Remove the logger key
        record_dict = record.__dict__
        if "logger" in record_dict:
            del record_dict["logger"]

        try:
            serializable_record = klogging.serialize_record(record)
        except Exception as e:
            log(
                f"Failed to serialize record: {e}",
                start_color=Ansi.LRED,
                level=logging.WARNING,
                extra={
                    "CodeRegion": "Logging",
                    "Func": "ElasticsearchHandler.emit",
                    "message": f"Failed to serialize record: {e}",
                    "error": f"{e}",
                    "traceback": traceback.format_exc(),
                    "record": str(record_dict),
                },
            )
            serializable_record = {
                "message": f"Failed to serialize record: {e}",
                "error": f"{e}",
                "traceback": traceback.format_exc(),
                "record": str(record_dict),
            }
        self.es.index(index=self.index, body=serializable_record)


def error_catcher(func):
    if asyncio.iscoroutinefunction(func):

        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                klogging.log(
                    f"Error in {func.__name__}: {e}",
                    start_color=klogging.Ansi.LRED,
                    level=logging.ERROR,
                    extra={
                        "error": f"{e}",
                    },
                )
                return await flash(
                    "error",
                    "An error occurred, please report this to the developer",
                    "error",
                )
    else:

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                klogging.log(
                    f"Error in {func.__name__}: {e}",
                    start_color=klogging.Ansi.LRED,
                    level=logging.ERROR,
                    extra={
                        "error": f"{e}",
                    },
                )
                return jsonify(
                    {
                        "error": "An error occurred, please report this to the developer",
                        "timestamp": datetime.now(),
                    }
                ), 500

    return wrapper
