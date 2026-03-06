# Kawata Frontend Logging Overhaul Plan (Revised)

## Executive Summary

This document outlines a comprehensive overhaul of the Kawata **frontend website server** logging system to address modern observability requirements. The frontend is being used as the **testing ground** for the new logging design and implementation before porting to the backend game server. Both systems use essentially the same logging system (originally written for the backend, then ported to the frontend).

**Project Context**:
- **Frontend**: Website server (profiles, leaderboards, beatmaps, etc.) - Current focus for overhaul
- **Backend**: Game server (API calls, game client connections, score submissions, etc.) - Will be ported later
- **Strategy**: Design and implement on frontend first (simpler codebase), then port to backend

**Key Changes from Original Plan**:
1. **No direct Elasticsearch submission** - All logs go through Logstash only
2. **Cleanup-first approach** - Fix existing logging issues before implementing new system
3. **Improved legacy system** - Have better logging while working on new implementation
4. **Remove duplicate logging** - Eliminate multiple stacktraces in single log events

## Current State Analysis

### Frontend Architecture
- **Frontend**: Python Quart/Flask web application serving the website interface
- **Current Logging**: Custom `klogging` class in [`objects/utils.py`](objects/utils.py:197) wrapping Python's logging module
- **Configuration**: YAML-based configuration in [`logging.yaml.example`](logging.yaml.example:1)
- **Logstash**: TCP handler on port 5040 sending to Elasticsearch
- **Direct ES**: [`ElasticsearchHandler`](objects/utils.py:674) in [`objects/utils.py`](objects/utils.py:674) - **TO BE REMOVED**

### Backend Architecture (For Context)
- **Backend**: Game server handling osu! client connections, score submission, leaderboards, chat, multiplayer
- **API**: Backend provides API that frontend consumes for scores, profiles, leaderboards, etc.
- **Cross-Service**: Frontend makes API calls to backend; request IDs must persist across service boundaries

### Current Logging Issues
The existing logging system suffers from:

1. **Critical Problem**: 1000+ fields in Elasticsearch due to duplicate stacktraces and local variable logging
   - The [`klogging.log()`](objects/utils.py:360) method adds extensive debug information for WARNING+ level logs
   - Local variables, stack traces, and verbose stacktraces are logged for every error
   - **Stacktrace duplication**: Errors logged multiple times with full local context in each

2. **Direct Elasticsearch Submission**: [`ElasticsearchHandler`](objects/utils.py:674) sends logs directly to ES
   - **TO BE REMOVED** - All logs should go through Logstash only
   - This handler is marked as "WIP" and "not recommended for production use"

3. **Poor Index Structure**: Current logstash config uses `log-%{service_name}-%{container_name}-%{method_name}`
   - Creates too many indices (one per log level/method)
   - No retention strategy or lifecycle management

4. **Wrong Separation**: Only dev/production indices, no separation for API logs, access logs, error logs

5. **No Retention Strategy**: All logs kept indefinitely, causing storage bloat

6. **Environment Detection**: Uses `SERVICE_NAME` and `CONTAINER_NAME` but these may not be consistently set

7. **Missing Features**:
   - No request ID correlation across frontend-backend service calls
   - No structured logging API for business events
   - No performance metrics collection
   - No error fingerprinting for grouping

### Pre-Migration Cleanup
Before implementing new system, all current indices must be **deleted and recreated** with proper structure:
```bash
# Delete bad indices
DELETE /log-*
# Fresh start with new index templates
```

## Architecture Overview

### New Logging Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Application   │──▶│  Structured Log  │──▶│   Log Router    │
│   Components    │    │    Generator     │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                        │
                       ┌────────────────────────────────┼────────────────────────────────┐
                       │                                │                                │
                ┌──────▼──────┐                 ┌───────▼──────┐                 ┌──────▼──────┐
                │  Metrics    │                 │ Observability│                 │  Sampling   │
                │  Collector  │                 │   Engine     │                 │   Manager   │
                └─────────────┘                 └──────────────┘                 └─────────────┘
                       │                                │                                │
                ┌──────▼──────┐                 ┌───────▼──────┐                 ┌──────▼──────┐
                │ Performance │                 │  Request ID  │                 │  Filtered   │
                │   Metrics   │                 │ Correlation  │                 │   Logs      │
                └─────────────┘                 └──────────────┘                 └─────────────┘
```

### Key Components

1. **Structured Log Generator**: Central hub for creating structured logs with consistent schema
2. **Metrics Collector**: Extracts and aggregates performance metrics
3. **Observability Engine**: Handles user tracking, request correlation, and comprehensive data collection
4. **Sampling Manager**: Implements intelligent log sampling to prevent ELK overload
5. **Log Router**: Routes logs to appropriate destinations based on type and environment

### Cross-Service Communication
- Frontend makes API calls to backend game server
- Request ID must persist across service boundaries via `X-Request-ID` header
- Backend may also call frontend for new features; request ID must persist in both directions

## Implementation Phases

### Phase 0: Cleanup Existing Implementation (Week 0)

#### 0.1 Remove Direct Elasticsearch Handler
**Action**: Delete the `ElasticsearchHandler` class from [`objects/utils.py`](objects/utils.py:674)

**Rationale**: 
- This handler is marked as "WIP" and "not recommended for production use"
- All logs should go through Logstash, not directly to Elasticsearch
- Direct submission bypasses Logstash routing and filtering capabilities

**Code to Remove** (lines 674-727 in [`objects/utils.py`](objects/utils.py:674)):
```python
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
        if 'logger' in record_dict:
            del record_dict['logger']
        
        try:
            serializable_record = klogging.serialize_record(record)
        except Exception as e:
            log(f"Failed to serialize record: {e}", start_color=Ansi.LRED, level=logging.WARNING, extra={
                'CodeRegion': 'Logging', "Func": "ElasticsearchHandler.emit",
                "message": f"Failed to serialize record: {e}",
                "error": f"{e}",
                "traceback": traceback.format_exc(),
                "record": str(record_dict),
                })
            serializable_record = {
                "message": f"Failed to serialize record: {e}",
                "error": f"{e}",
                "traceback": traceback.format_exc(),
                "record": str(record_dict),
                }
        self.es.index(index=self.index, body=serializable_record)
```

#### 0.2 Fix Duplicate Logging in `klogging.log()`
**Action**: Clean up the [`klogging.log()`](objects/utils.py:360) method to remove duplicate stacktrace logging

**Current Issues**:
- Lines 470-502 add extensive debug information for WARNING+ level logs
- Stacktraces, local variables, and verbose stacktraces are logged for every error
- This creates 1000+ fields in Elasticsearch

**Code to Modify** (lines 470-502 in [`objects/utils.py`](objects/utils.py:470)):
```python
# REMOVE THIS ENTIRE BLOCK:
if log_level >= 21:
    # Add calling function's arguments to the 'extra' fields
    extra['args'] = arg_info.args
    extra['varargs'] = arg_info.varargs
    extra['keywords'] = arg_info.keywords
    extra['locals'] = arg_info.locals
    extra['func'] = info.function
    # Add stack trace to the 'extra' fields
    stack_info = inspect.stack()
    serializable_stack = [{'filename': frame.filename, 'lineno': frame.lineno, 'function': frame.function, 'code_context': frame.code_context, 'index': frame.index} for frame in stack_info]
    extra['stack_trace'] = json.dumps(traceback.format_stack())
    extra['stack'] = json.dumps(serializable_stack)

    if log_level >= 40:
        # Add the 'exc_info' to the 'extra' fields
        extra['verbose_stacktrace'] = {}
        if info.function in frame.f_globals:
            extra['verbose_stacktrace']['func_signature'] = str(inspect.signature(frame.f_globals[info.function]))
            extra['verbose_stacktrace']['func_source'] = inspect.getsource(frame.f_globals[info.function])
        extra['verbose_stacktrace']['exc_info'] = traceback.format_exc()
        extra['verbose_stacktrace']['exc_type'] = str(sys.exc_info()[0])
        extra['verbose_stacktrace']['exception'] = str(traceback.format_exception(*sys.exc_info()))
        extra['verbose_stacktrace']['exception_only'] = str(traceback.format_exception_only(sys.exc_info()[0], sys.exc_info()[1]))
        extra['verbose_stacktrace']['error'] = str(sys.exc_info()[1])
        extra['verbose_stacktrace']['error_traceback'] = str(traceback.format_exc())
        extra['verbose_stacktrace']['error_stack'] = serializable_stack
        extra['verbose_stacktrace']['error_locals'] = str(arg_info.locals)
        extra['verbose_stacktrace']['error_args'] = str(arg_info.args)
        extra['verbose_stacktrace']['error_varargs'] = str(arg_info.varargs)
        extra['verbose_stacktrace']['error_keywords'] = str(arg_info.keywords)
        extra['verbose_stacktrace']['error_message'] = msg
        extra['verbose_stacktrace']['error_level'] = log_level

        extra['verbose_stacktrace'] = json.dumps(extra['verbose_stacktrace'], indent=2)
```

**Replacement** (minimal logging for errors only):
```python
# Only add stack trace for ERROR level logs (not WARNING)
if log_level >= 40:
    # Add minimal stack trace information
    stack_info = inspect.stack()
    if stack_info:
        # Only include the immediate caller frame
        caller_frame = stack_info[1] if len(stack_info) > 1 else stack_info[0]
        extra['caller_file'] = caller_frame.filename
        extra['caller_line'] = caller_frame.lineno
        extra['caller_function'] = caller_frame.function
    
    # Add exception info if available
    exc_info = sys.exc_info()
    if exc_info[0] is not None:
        extra['error_type'] = exc_info[0].__name__
        extra['error_message'] = str(exc_info[1])
        extra['stack_trace'] = traceback.format_exc()
```

#### 0.3 Delete Corrupted Elasticsearch Indices
**Action**: Delete all corrupted indices with 1000+ fields

```bash
# Delete all log indices
DELETE /log-*
# Delete monitoring indices
DELETE /.monitoring-*
```

#### 0.4 Delete Old Index Templates
**Action**: Start fresh with new index templates

```bash
DELETE /_index_template/*
```

#### 0.5 Create Legacy Index Templates with Better Settings
**Action**: Create improved legacy index templates while working on new implementation

```json
{
  "index_patterns": ["log-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 1,
      "index.lifecycle.name": "logs-policy-legacy",
      "index.lifecycle.rollover_alias": "log-legacy"
    },
    "mappings": {
      "dynamic": false,
      "properties": {
        "@timestamp": {"type": "date"},
        "message": {"type": "text"},
        "level": {"type": "keyword"},
        "logger": {"type": "keyword"},
        "service_name": {"type": "keyword"},
        "container_name": {"type": "keyword"}
      }
    }
  }
}
```

#### 0.6 Create Legacy Lifecycle Policy
```json
{
  "policy": "logs-policy-legacy",
  "phases": {
    "hot": {
      "min_age": "0d",
      "actions": {
        "rollover": {
          "max_primary_shard_size": "50GB",
          "max_age": "1d"
        }
      }
    },
    "delete": {
      "min_age": "7d",
      "actions": {
        "delete": {}
      }
    }
  }
}
```

### Phase 1: Core Infrastructure (Week 1-2)

#### 1.1 Enhanced Configuration System
- Extend [`logging.yaml.example`](logging.yaml.example:1) with new structured handlers
- Add sampling configuration
- Environment-specific routing rules

```yaml
# New logging.yaml additions
handlers:
  # Console output - always available as fallback
  console:
    class: logging.StreamHandler
    level: DEBUG
    formatter: detailed
    stream: ext://sys.stdout

  # JSON file fallback - when Logstash/ELK is down
  json_file:
    class: logging.handlers.RotatingFileHandler
    level: INFO
    formatter: json_compact
    filename: logs/kawata.json
    maxBytes: 104857600  # 100MB
    backupCount: 10

  # Logstash (TCP) - all structured logs sent here
  # Logstash handles routing to appropriate Elasticsearch indices
  logstash:
    class: pythonjsonlogger.handlers.JsonSocketHandler
    level: INFO
    formatter: structured_json
    host: localhost
    port: 5040
    transport: socket.SOCK_STREAM

formatters:
  detailed:
    format: '[%(asctime)s] %(name)s - %(levelname)s - %(message)s'

  json_compact:
    class: pythonjsonlogger.jsonlogger.JsonFormatter
    format: '%(asctime)s %(levelname)s %(message)s %(request_id)s %(user_id)s'

  structured_json:
    class: objects.logging.formatters.StructuredJSONFormatter
    format: '%(asctime)s %(request_id)s %(user_id)s %(levelname)s %(message)s'
    json_fields:
      '@timestamp': '@timestamp'
      'request.id': 'request_id'
      'user.id': 'user_id'
      'service.name': 'service_name'
      'service.environment': 'environment'
      'event.type': 'event_type'
      'level': 'level'
```

#### 1.2 Request ID Generation and Correlation
- Implement UUID-based request ID generation
- Add request ID to all logs within the same request lifecycle
- Cross-service correlation headers (for frontend-backend calls)
- Support both synchronous and asynchronous contexts

```python
# objects/logging/correlation.py
from contextvars import ContextVar
import uuid

_request_context = ContextVar('request_context', default={})

class RequestCorrelation:
    @staticmethod
    def generate_request_id() -> str:
        return f"req-{uuid.uuid4()}"

    @staticmethod
    def get_current_request_id() -> Optional[str]:
        try:
            # Try contextvars first (works with async)
            return _request_context.get().get('request_id')
        except:
            # Fallback to Quart's g object
            return getattr(g, 'request_id', None)

    @staticmethod
    def set_request_id(request_id: str):
        # Set in both Quart g (for compatibility) and contextvars (for async)
        g.request_id = request_id
        _request_context.set({'request_id': request_id})

    @staticmethod
    def extract_from_headers(headers: dict) -> Optional[str]:
        """Extract request ID from incoming X-Request-ID header (cross-service calls)"""
        return headers.get('X-Request-ID')

    @staticmethod
    def inject_into_headers(headers: dict) -> dict:
        """Add request ID to outgoing headers (making calls to backend)"""
        request_id = RequestCorrelation.get_current_request_id()
        if request_id:
            headers['X-Request-ID'] = request_id
            headers['X-Trace-ID'] = request_id  # For distributed tracing
        return headers
```

#### 1.3 Environment Detection Enhancement
- Automatic environment detection from service naming
- Dynamic index naming for ELK

```python
# objects/logging/environment.py
class EnvironmentDetector:
    @staticmethod
    def detect_environment() -> dict:
        service_name = glob.config.SERVICE_NAME
        container_name = glob.config.CONTAINER_NAME

        if 'dev' in service_name.lower() or 'dev' in container_name.lower():
            env = 'development'
        elif 'staging' in service_name.lower():
            env = 'staging'
        else:
            env = 'production'

        return {
            'environment': env,
            'service_name': service_name,
            'container_name': container_name,
            'index_prefix': f"logs-{service_name.lower()}-{container_name.lower()}"
        }
```

### Phase 2: Structured Logging API (Week 3-4)

#### 2.1 New Structured Logging Interface
- Maintain backward compatibility with existing `klogging.log()` calls
- Add new structured logging methods

```python
# objects/logging/structured.py
class StructuredLogger:
    @staticmethod
    def log_event(event_type: str, data: dict, level: int = logging.INFO, **kwargs):
        """Log structured events with custom data"""
        extra = {
            'event_type': event_type,
            'event_data': data,
            'request_id': RequestCorrelation.get_current_request_id(),
            'user_id': UserContext.get_current_user_id(),
            **kwargs
        }
        klogging.log(f"Event: {event_type}", extra=extra, level=level)

    @staticmethod
    def log_score(score_data: dict):
        """Log score-related events"""
        StructuredLogger.log_event('score_submission', score_data)

    @staticmethod
    def log_admin_action(action: str, target_user_id: int, details: dict):
        """Log admin operations"""
        StructuredLogger.log_event('admin_action', {
            'action': action,
            'target_user_id': target_user_id,
            'admin_user_id': UserContext.get_current_user_id(),
            **details
        })
```

#### 2.2 User Context System
- Flexible user tracking that works with current session system
- Anonymous user handling

```python
# objects/logging/user_context.py
class UserContext:
    @staticmethod
    def get_current_user_id() -> Optional[int]:
        """Extract user ID from current session/request context"""
        try:
            if hasattr(g, 'user') and g.user:
                return g.user.id
            if session.get('user_data'):
                return session['user_data'].get('id')
            return None
        except:
            return None

    @staticmethod
    def get_user_context() -> dict:
        """Get comprehensive user context"""
        user_id = UserContext.get_current_user_id()
        return {
            'user_id': user_id,
            'session_id': session.get('session_id'),
            'ip_address': request.remote_addr if request else None,
            'user_agent': request.headers.get('User-Agent') if request else None,
        }
```

### Phase 3: Metrics and Performance Tracking (Week 5-6)

#### 3.1 Performance Metrics Collector
- Response time tracking
- API performance monitoring
- Database query metrics

```python
# objects/logging/metrics/performance.py
class PerformanceMetrics:
    @staticmethod
    def track_request_performance(func):
        """Decorator to track function performance"""
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time

                StructuredLogger.log_event('performance_metric', {
                    'operation': func.__name__,
                    'duration_ms': duration * 1000,
                    'success': True
                }, level=logging.DEBUG)

                return result
            except Exception as e:
                duration = time.time() - start_time
                StructuredLogger.log_event('performance_metric', {
                    'operation': func.__name__,
                    'duration_ms': duration * 1000,
                    'success': False,
                    'error': str(e)
                }, level=logging.WARNING)
                raise
        return wrapper
```

#### 3.2 API Metrics
- Endpoint-specific metrics
- Error rate tracking
- Request volume analysis

```python
# objects/logging/metrics/api.py
class APIMetrics:
    @staticmethod
    def log_api_request(endpoint: str, method: str, status_code: int, duration: float):
        StructuredLogger.log_event('api_request', {
            'endpoint': endpoint,
            'method': method,
            'status_code': status_code,
            'duration_ms': duration * 1000,
            'response_category': APIMetrics.get_response_category(status_code)
        })

    @staticmethod
    def get_response_category(status_code: int) -> str:
        if status_code < 200:
            return 'informational'
        elif status_code < 300:
            return 'success'
        elif status_code < 400:
            return 'redirection'
        elif status_code < 500:
            return 'client_error'
        else:
            return 'server_error'
```

### Phase 4: Observability Enhancement (Week 7-8)

#### 4.1 Comprehensive Request Logging
- Referrer tracking
- Geographic data integration
- Device and browser information

```python
# objects/logging/observability/request_tracker.py
class RequestTracker:
    @staticmethod
    def extract_request_data(request) -> dict:
        return {
            'url': str(request.url),
            'method': request.method,
            'headers': dict(request.headers),
            'query_params': dict(request.args),
            'referrer': request.headers.get('Referer'),
            'user_agent': request.headers.get('User-Agent'),
            'accept_language': request.headers.get('Accept-Language'),
            'ip_address': request.headers.get('X-Forwarded-For', request.remote_addr),
            'cloudflare_country': request.headers.get('CF-IPCountry'),
            'cloudflare_ray': request.headers.get('CF-RAY'),
        }

    @staticmethod
    def extract_referrer_source(referrer: str) -> str:
        """Extract search engine or source from referrer"""
        if not referrer:
            return 'direct'

        parsed = urlparse(referrer)
        domain = parsed.netloc.lower()

        search_engines = {
            'google': ['google.com', 'google.co.uk', 'google.ca'],
            'bing': ['bing.com'],
            'yahoo': ['yahoo.com', 'search.yahoo.com'],
            'duckduckgo': ['duckduckgo.com'],
        }

        for engine, domains in search_engines.items():
            if any(d in domain for d in domains):
                return engine

        return 'other'
```

#### 4.2 Error Correlation
- Exception chaining
- Request context in errors
- Error fingerprinting

```python
# objects/logging/observability/error_correlation.py
class ErrorCorrelation:
    @staticmethod
    def log_error(error: Exception, context: dict = None):
        error_fingerprint = ErrorCorrelation.generate_fingerprint(error)

        StructuredLogger.log_event('application_error', {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'error_fingerprint': error_fingerprint,
            'stack_trace': traceback.format_exc(),
            'request_context': context or {},
            'user_context': UserContext.get_user_context(),
        }, level=logging.ERROR)

    @staticmethod
    def generate_fingerprint(error: Exception) -> str:
        """Generate consistent fingerprint for error grouping"""
        tb = traceback.extract_tb(error.__traceback__)
        if tb:
            last_frame = tb[-1]
            return hashlib.md5(
                f"{type(error).__name__}:{last_frame.filename}:{last_frame.lineno}".encode()
            ).hexdigest()
        return hashlib.md5(str(error).encode()).hexdigest()
```

### Phase 5: Log Sampling & High-Volume Handling (Week 9-10)

#### 5.1 Adaptive Sampling (High Traffic Only)
- **Normal Traffic** (<1000 req/min): Send all logs
- **High Traffic** (>1000 req/min): Sample access logs, keep everything else
- **Error Logs**: Never sampled, always sent to `logs-kawata-errors`
- **Event Logs**: Never sampled, always sent to `logs-kawata-events`

```python
# objects/logging/sampling/traffic_monitor.py
class TrafficMonitor:
    def __init__(self, window_size: int = 60):  # 60 second window
        self.request_count = 0
        self.window_start = time.time()
        self.high_traffic_threshold = 1000  # requests per minute
        self.is_high_traffic = False

    def record_request(self):
        current_time = time.time()
        elapsed = current_time - self.window_start

        if elapsed >= self.window_size:
            # Calculate requests per minute
            req_per_minute = (self.request_count / elapsed) * 60
            self.is_high_traffic = req_per_minute > self.high_traffic_threshold
            self.request_count = 0
            self.window_start = current_time
        else:
            self.request_count += 1

    def should_sample_access_logs(self) -> bool:
        """Only sample access logs during high traffic"""
        return self.is_high_traffic
```

#### 5.2 Separate Index Strategy
Instead of sampling core data, use separate indices with different retention:

```python
# objects/logging/handlers/logstash_router.py
class LogstashRouterHandler(logging.Handler):
    """Routes logs to appropriate Logstash destination based on event type"""
    
    def emit(self, record):
        # All logs go through Logstash - no direct ES submission
        # Logstash will route based on event_type and level
        self.send_to_logstash(record)
```

## File Structure

```
objects/logging/
├── __init__.py                      # Main API exports
├── structured.py                    # StructuredLogger class (main API)
├── correlation.py                   # RequestCorrelation (shared)
├── environment.py                   # EnvironmentDetector (shared)
├── user_context.py                  # UserContext (shared)
│
├── formatters/
│   ├── __init__.py
│   ├── structured_json.py           # Main structured format
│   ├── access_json.py               # Lightweight access log format
│   └── error_json.py                # Error-specific format
│
├── handlers/
│   ├── __init__.py
│   ├── logstash_router.py           # Routes logs to Logstash (NO direct ES)
│   ├── fallback_json.py             # JSON file fallback (ELK down)
│   └── console.py                   # Console output handler
│
├── metrics/
│   ├── __init__.py
│   ├── performance.py               # Performance tracking decorator
│   ├── api.py                       # API metrics
│   └── collector.py                 # Metrics aggregation
│
├── observability/
│   ├── __init__.py
│   ├── request_tracker.py           # Extract request metadata
│   ├── error_correlation.py         # Error fingerprinting
│   └── user_activity.py             # User event tracking
│
├── sampling/
│   ├── __init__.py
│   ├── traffic_monitor.py           # High-traffic detection
│   └── access_sampler.py            # Access log sampling only
│
└── config/
    ├── __init__.py
    └── logging_config.py            # Load YAML, setup handlers
```

## Code Examples

### Basic Structured Logging

```python
from objects.logging import StructuredLogger

# Log custom score data
StructuredLogger.log_score({
    'user_id': 12345,
    'beatmap_id': 67890,
    'score': 950000,
    'accuracy': 98.5,
    'mods': ['HD', 'HR']
})

# Log admin action
StructuredLogger.log_admin_action('ban_user', target_user_id=54321, details={
    'reason': 'cheating',
    'duration': 'permanent'
})
```

### Performance Tracking

```python
from objects.logging.metrics import PerformanceMetrics

@PerformanceMetrics.track_request_performance
async def submit_score(score_data):
    # Score submission logic
    pass
```

### Request Middleware

```python
# In main.py or middleware
@app.before_request
async def setup_request_logging():
    # Generate request ID
    request_id = RequestCorrelation.generate_request_id()
    RequestCorrelation.set_request_id(request_id)

    # Log request start
    StructuredLogger.log_event('request_start', {
        'method': request.method,
        'path': request.path,
        'user_agent': request.headers.get('User-Agent'),
        'ip': request.remote_addr
    })

@app.after_request
async def log_request_completion(response):
    # Enhanced access logging
    await klogging.access_log_enhanced(request, response)
    return response
```

### Cross-Service API Calls (Frontend → Backend)

```python
# When making API calls to backend, inject request ID
async def call_backend_api(endpoint: str, data: dict):
    headers = {}
    RequestCorrelation.inject_into_headers(headers)
    
    async with glob.http.post(
        f"{glob.config.BACKEND_URL}{endpoint}",
        json=data,
        headers=headers
    ) as resp:
        return await resp.json()
```

## ELK Configuration

### New Index Structure (Fix for 1000+ Fields Problem)

Instead of one massive index with all log types, use **separate indices by category**:

```
Logs Generated
├─ Access logs (high volume) → logs-kawata-access-YYYY.MM.dd (7 day retention)
├─ API/Event logs → logs-kawata-events-YYYY.MM.dd (30 day retention)
├─ Error logs → logs-kawata-errors-YYYY.MM.dd (90 day retention)
├─ Score submissions → logs-kawata-scores-YYYY.MM.dd (180 day retention)
└─ Client logs (backend) → logs-kawata-client-YYYY.MM.dd (30 day retention)

Each index: ~50-100 fields instead of 1000+
```

### Index Template: Core Events (Low Volume, Full Data)

```json
{
  "index_patterns": ["logs-kawata-events-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 1,
      "index.lifecycle.name": "logs-policy-events",
      "index.lifecycle.rollover_alias": "logs-kawata-events"
    },
    "mappings": {
      "properties": {
        "@timestamp": {"type": "date"},
        "request_id": {"type": "keyword", "index": true},
        "user_id": {"type": "keyword", "index": true},
        "event_type": {"type": "keyword", "index": true},
        "service_name": {"type": "keyword"},
        "environment": {"type": "keyword"},
        "duration_ms": {"type": "float"},
        "success": {"type": "boolean"},
        "event_data": {
          "type": "object",
          "enabled": true
        },
        "error": {"type": "text"},
        "error_fingerprint": {"type": "keyword"}
      }
    }
  }
}
```

### Index Template: Access Logs (High Volume, Simple)

```json
{
  "index_patterns": ["logs-kawata-access-*"],
  "template": {
    "settings": {
      "number_of_shards": 3,
      "number_of_replicas": 0,
      "index.lifecycle.name": "logs-policy-access",
      "index.lifecycle.rollover_alias": "logs-kawata-access"
    },
    "mappings": {
      "properties": {
        "@timestamp": {"type": "date"},
        "request_id": {"type": "keyword"},
        "method": {"type": "keyword"},
        "path": {"type": "keyword"},
        "status_code": {"type": "integer"},
        "duration_ms": {"type": "float"},
        "user_id": {"type": "keyword"},
        "ip_address": {"type": "ip"},
        "user_agent": {"type": "text"},
        "referrer": {"type": "keyword"},
        "country": {"type": "keyword"}
      }
    }
  }
}
```

### Index Template: Errors (Detailed Context)

```json
{
  "index_patterns": ["logs-kawata-errors-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 1,
      "index.lifecycle.name": "logs-policy-errors"
    },
    "mappings": {
      "properties": {
        "@timestamp": {"type": "date"},
        "request_id": {"type": "keyword"},
        "error_type": {"type": "keyword"},
        "error_message": {"type": "text"},
        "error_fingerprint": {"type": "keyword"},
        "stack_trace": {"type": "text"},
        "user_id": {"type": "keyword"},
        "user_context": {"type": "object"},
        "request_context": {"type": "object"},
        "service_name": {"type": "keyword"},
        "environment": {"type": "keyword"}
      }
    }
  }
}
```

### Index Lifecycle Policy: Access Logs (Auto Roll & Delete)

```json
{
  "policy": "logs-policy-access",
  "phases": {
    "hot": {
      "min_age": "0d",
      "actions": {
        "rollover": {
          "max_primary_shard_size": "50GB",
          "max_age": "1d"
        }
      }
    },
    "delete": {
      "min_age": "7d",
      "actions": {
        "delete": {}
      }
    }
  }
}
```

### Index Lifecycle Policy: Events (Longer Retention)

```json
{
  "policy": "logs-policy-events",
  "phases": {
    "hot": {
      "min_age": "0d",
      "actions": {
        "rollover": {
          "max_primary_shard_size": "10GB",
          "max_age": "7d"
        }
      }
    },
    "warm": {
      "min_age": "7d",
      "actions": {
        "set_priority": {"priority": 50}
      }
    },
    "delete": {
      "min_age": "30d",
      "actions": {
        "delete": {}
      }
    }
  }
}
```

### Logstash Pipeline (Route by Index)

```
input {
  tcp {
    port => 5040
    codec => json_lines
  }
}

filter {
  # Add geographic data from IP
  if [ip_address] {
    geoip {
      source => "ip_address"
      target => "geoip"
    }
  }

  # Extract country from geoip or Cloudflare header
  if [geoip][country_code2] {
    mutate {
      add_field => { "country" => "%{[geoip][country_code2]}" }
    }
  }
}

output {
  # Route access logs to separate high-volume index
  if [event_type] == "request_complete" or [event_type] == "access_log" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "logs-kawata-access-%{+YYYY.MM.dd}"
    }
  }
  # Errors go to dedicated error index
  else if [@level] == "ERROR" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "logs-kawata-errors-%{+YYYY.MM.dd}"
    }
  }
  # Everything else goes to events
  else {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "logs-kawata-events-%{+YYYY.MM.dd}"
    }
  }
}
```

## Migration Strategy

### Phase 0: Cleanup Existing Implementation (Week 0)
1. **Remove direct Elasticsearch handler** - Delete `ElasticsearchHandler` from [`objects/utils.py`](objects/utils.py:674)
2. **Fix duplicate logging** - Clean up [`klogging.log()`](objects/utils.py:360) to remove duplicate stacktraces
3. **Delete corrupted indices** - `DELETE /log-*`
4. **Delete old templates** - `DELETE /_index_template/*`
5. **Create legacy templates** - Improved settings for existing code
6. **Port cleaned-up implementation** - Deploy to frontend

### Phase 1: Infrastructure Setup
1. Deploy new logging classes alongside existing system
2. Create new Elasticsearch index templates with proper structure
3. Update logging.yaml with new handlers:
   - Console output (always active)
   - JSON file fallback (always active)
   - Elasticsearch events (test in dev)
4. Test in development environment

### Phase 2: Gradual Adoption (Frontend)
1. Enable structured logging for new features only
2. Migrate high-value logs first:
   - Score submissions (events index)
   - Admin actions (events index)
   - API errors (errors index)
3. Keep `klogging.log()` for generic logging (goes to command-line for now)
4. **Don't migrate access logs yet** - still use old format

### Phase 3: Full Frontend Migration
1. Enable access logs to new index
2. Monitor ELK ingestion rates
3. Adjust sampling thresholds based on actual traffic
4. Verify all dashboards work with new indices
5. Document logging patterns for team

### Phase 4: Backend Preparation
1. Extend logging system for backend needs (client connections, game metrics)
2. Add backend-specific indices if needed
3. Test cross-service request ID passing
4. Plan backend deployment

### Fallback Logging (All Phases)
- Console output always works (developers see errors immediately)
- JSON file logging kicks in if ELK connection fails
- No logs lost even if Elasticsearch is down

### Backward Compatibility

```python
# Old calls still work
klogging.log("User logged in", extra={'user_id': 123})
# Goes to: console + JSON file (if ES down) + eventually ES

# New structured calls
StructuredLogger.log_event('user_login', {'user_id': 123})
# Goes to: console + appropriate ES index (events/errors/access) + JSON file fallback

# Both routes feed same handlers, so even old code uses new system
```

## Testing Approach

### Unit Tests
```python
# tests/test_logging.py
def test_structured_logging():
    with patch('objects.logging.structured.klogging.log') as mock_log:
        StructuredLogger.log_score({'user_id': 1, 'score': 100})
        mock_log.assert_called_once()
        args, kwargs = mock_log.call_args
        assert kwargs['extra']['event_type'] == 'score_submission'

def test_request_correlation():
    request_id = RequestCorrelation.generate_request_id()
    RequestCorrelation.set_request_id(request_id)
    assert RequestCorrelation.get_current_request_id() == request_id
```

### Integration Tests
- Test full request lifecycle logging
- Verify ELK ingestion and parsing
- Performance impact testing
- Sampling accuracy tests

### Load Testing
- Simulate high-volume logging scenarios
- Test sampling under load
- Monitor memory usage and CPU impact

## Success Metrics

1. **ELK Performance**: Maintain <5% CPU overhead for logging
2. **Data Completeness**: >95% of requests have full observability data
3. **Query Performance**: Dashboard queries complete in <2 seconds
4. **Error Tracking**: 100% of errors captured with full context
5. **Sampling Accuracy**: Sampled logs represent true distribution within 5%

## Risk Mitigation

1. **ELK Overload**: Implement sampling from day one
2. **Performance Impact**: Profile and optimize serialization
3. **Data Loss**: Dual logging during migration
4. **Complexity**: Start with simple structured logs, add complexity gradually

## Timeline and Milestones

### Frontend Implementation (Testing Ground)
- **Week 0**: Cleanup existing implementation (remove direct ES, fix duplicate logging, delete corrupted indices, create legacy templates)
- **Week 1-2**: Core infrastructure (request ID, correlation, fallback handlers)
- **Week 3-4**: Structured logging API (StructuredLogger, UserContext)
- **Week 5-6**: Metrics and performance tracking decorators
- **Week 7-8**: Observability enhancements (referrer tracking, error fingerprinting)
- **Week 9-10**: Sampling and high-traffic handling (only when needed)
- **Week 11-12**: Frontend testing, dashboards, production deployment

### Backend Implementation (Future - Port from Frontend)
- **Week 13+**: Extend logging for backend needs
- Game client connection tracking
- Score submission pipeline
- High-volume event handling
- Performance optimization for backend scale
- Cross-service request ID correlation testing

This overhaul will transform Kawata's logging from basic text output to a comprehensive observability platform, enabling data-driven decisions and proactive issue resolution. The frontend serves as the testing ground, ensuring the system is solid before porting to the backend.
